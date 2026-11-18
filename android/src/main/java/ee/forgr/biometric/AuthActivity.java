package ee.forgr.biometric;

import android.app.KeyguardManager;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.util.Base64;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.lifecycle.ViewModel;
import androidx.lifecycle.ViewModelProvider;
import ee.forgr.biometric.capacitornativebiometric.R;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Objects;
import java.util.concurrent.Executor;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import org.json.JSONObject;

public class AuthActivity extends AppCompatActivity {

    private static final String AUTH_KEY_ALIAS = "NativeBiometricAuthKey";
    private static final String AUTH_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int CREDENTIAL_GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final String SHARED_PREFS_NAME = "NativeBiometricSharedPreferences";
    private static final int NO_PROTECTED_CREDENTIALS = 21;
    private static final int UNKNOWN_ACCESS_CONTROL = -1;
    private static final int BIOMETRY_CURRENT_SET = 1;
    private static final int BIOMETRY_ANY = 2;

    // AndroidX keeps the original prompt across configuration changes.
    public static final class PromptState extends ViewModel {

        Cipher authCipher;
        Cipher credentialCipher;
        SecretKey credentialKeyAwaitingAuthentication;
        String credentialAlias;
        String replacementAlias;
        String encryptedCredentials;
        Object writeToken;
        int accessControl;
        int previousAccessControl;
        int failedAttempts;
        boolean started;
    }

    private PromptState promptState;
    private String mode;
    private String credentialServer;
    private int maxAttempts;
    private boolean activityFinished;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_auth_acitivy);
        promptState = new ViewModelProvider(this).get(PromptState.class);
        setResult(RESULT_CANCELED, activityResult());

        mode = getIntent().getStringExtra("mode");
        if (mode == null) mode = "verify";
        credentialServer = getIntent().getStringExtra("server");

        int rawMaxAttempts = getIntent().getIntExtra("maxAttempts", 1);
        maxAttempts = Math.max(1, Math.min(5, rawMaxAttempts));

        Executor executor;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            executor = this.getMainExecutor();
        } else {
            executor = new Executor() {
                @Override
                public void execute(Runnable command) {
                    new Handler().post(command);
                }
            };
        }

        BiometricPrompt.PromptInfo.Builder builder = new BiometricPrompt.PromptInfo.Builder()
            .setTitle(getIntent().hasExtra("title") ? Objects.requireNonNull(getIntent().getStringExtra("title")) : "Authenticate")
            .setSubtitle(getIntent().hasExtra("subtitle") ? getIntent().getStringExtra("subtitle") : null)
            .setDescription(getIntent().hasExtra("description") ? getIntent().getStringExtra("description") : null);

        boolean verify = "verify".equals(mode);
        boolean useFallback = verify && getIntent().getBooleanExtra("useFallback", false);
        int[] allowedTypes = verify ? getIntent().getIntArrayExtra("allowedBiometryTypes") : null;
        int authenticators = resolvePromptAuthenticators(allowedTypes, useFallback, Build.VERSION.SDK_INT);
        builder.setAllowedAuthenticators(authenticators);

        boolean deviceCredentialAllowed = allowsDeviceCredential(authenticators);
        if (!deviceCredentialAllowed) {
            String negativeText = getIntent().getStringExtra("negativeButtonText");
            builder.setNegativeButtonText(negativeText != null ? negativeText : "Cancel");
        }

        boolean verifyWithoutCrypto = verify && deviceCredentialAllowed;
        BiometricPrompt.PromptInfo promptInfo;
        try {
            promptInfo = builder.build();
        } catch (IllegalArgumentException e) {
            finishActivity("error", 0, "Invalid biometric prompt configuration");
            return;
        }

        BiometricPrompt biometricPrompt = new BiometricPrompt(
            this,
            executor,
            new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                    super.onAuthenticationError(errorCode, errString);
                    // Handle lockout cases explicitly
                    if (errorCode == BiometricPrompt.ERROR_LOCKOUT || errorCode == BiometricPrompt.ERROR_LOCKOUT_PERMANENT) {
                        int pluginErrorCode = convertToPluginErrorCode(errorCode);
                        finishActivity("error", pluginErrorCode, errString.toString());
                        return;
                    }
                    int pluginErrorCode = convertToPluginErrorCode(errorCode);
                    finishActivity("error", pluginErrorCode, errString.toString());
                }

                @Override
                public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    if (activityFinished) return;
                    if ("setSecureCredentials".equals(mode) || "getSecureCredentials".equals(mode)) {
                        completeCredentialOperation(result);
                    } else {
                        if (!verifyWithoutCrypto && !validateCryptoObject(result)) {
                            finishActivity("error", 10, "Biometric security check failed");
                            return;
                        }
                        finishActivity();
                    }
                }

                @Override
                public void onAuthenticationFailed() {
                    super.onAuthenticationFailed();
                    if (activityFinished) return;
                    promptState.failedAttempts++;
                    if (promptState.failedAttempts >= maxAttempts) {
                        // Do NOT call cancelAuthentication() here, it triggers onAuthenticationError(ERROR_CANCELED)
                        // which would call finishActivity again, overwriting our result.
                        // finish() alone closes the Activity and dismisses the BiometricPrompt automatically.
                        // We cannot use error code 4 here; it is reserved for Android system lockout (30s) from onAuthenticationError.
                        finishActivity("error", 10, "Authentication Failed");
                    }
                }
            }
        );

        if (promptState.started) {
            // The constructor reattaches this Activity's callback to the running prompt.
            return;
        }
        if (savedInstanceState != null) {
            finishActivity("error", 10, "Biometric authentication was interrupted");
            return;
        }

        // The identity prompt can verify the user without unlocking a protected credential.
        if (verifyWithoutCrypto) {
            promptState.started = true;
            biometricPrompt.authenticate(promptInfo);
            return;
        }

        BiometricPrompt.CryptoObject cryptoObject;
        if ("setSecureCredentials".equals(mode)) {
            cryptoObject = createCredentialEncryptCryptoObject();
        } else if ("getSecureCredentials".equals(mode)) {
            cryptoObject = createCredentialDecryptCryptoObject();
        } else {
            if (!canPrepareVerificationKey()) {
                return;
            }
            cryptoObject = createCryptoObject();
        }
        if (promptState.credentialKeyAwaitingAuthentication != null) {
            promptState.started = true;
            biometricPrompt.authenticate(promptInfo);
        } else if (cryptoObject != null) {
            promptState.started = true;
            biometricPrompt.authenticate(promptInfo, cryptoObject);
        } else {
            finishActivity("error", 0, "Biometric crypto object unavailable");
        }
    }

    void finishActivity() {
        finishActivity("success", null, null);
    }

    void finishActivity(String result, Integer errorCode, String errorDetails) {
        // Prevent multiple calls to finishActivity() from being called twice.
        if (activityFinished) return;
        activityFinished = true;
        finishCredentialWrite();

        Intent intent = activityResult();
        intent.putExtra("result", result);
        if (errorCode != null) {
            intent.putExtra("errorCode", String.valueOf(errorCode));
        }
        if (errorDetails != null) {
            intent.putExtra("errorDetails", errorDetails);
        }
        setResult(RESULT_OK, intent);
        finish();
    }

    private Intent activityResult() {
        Intent result = new Intent();
        result.putExtra(BiometricActivityRequests.EXTRA_REQUEST_ID, getIntent().getStringExtra(BiometricActivityRequests.EXTRA_REQUEST_ID));
        return result;
    }

    @Override
    protected void onDestroy() {
        activityFinished = true;
        if (!isChangingConfigurations()) {
            finishCredentialWrite();
        }
        super.onDestroy();
    }

    private boolean canPrepareVerificationKey() {
        int availability = BiometricManager.from(this).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        if (availability == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED || !getSystemService(KeyguardManager.class).isDeviceSecure()) {
            finishActivity("error", 3, "No biometrics enrolled");
            return false;
        }
        if (
            availability == BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE || availability == BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE
        ) {
            finishActivity("error", 1, "Biometric hardware unavailable");
            return false;
        }
        return true;
    }

    private BiometricPrompt.CryptoObject createCryptoObject() {
        try {
            promptState.authCipher = createCipher();
            return new BiometricPrompt.CryptoObject(promptState.authCipher);
        } catch (GeneralSecurityException | IOException | ProviderException | IllegalStateException e) {
            return null;
        }
    }

    private Cipher createCipher() throws GeneralSecurityException, IOException {
        SecretKey secretKey = getOrCreateSecretKey();
        Cipher cipher = Cipher.getInstance(AUTH_TRANSFORMATION);
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        } catch (KeyPermanentlyInvalidatedException e) {
            deleteSecretKey();
            secretKey = getOrCreateSecretKey();
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }
        return cipher;
    }

    private SecretKey getOrCreateSecretKey() throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        try {
            keyStore.load(null);
        } catch (CertificateException e) {
            throw new GeneralSecurityException("Failed to load AndroidKeyStore", e);
        }
        SecretKey key = findCredentialKey(keyStore, AUTH_KEY_ALIAS);
        if (key == null) {
            return generateCredentialKey(AUTH_KEY_ALIAS, true);
        }
        KeyInfo info = getKeyInfo(key);
        if (!info.isUserAuthenticationRequired()) {
            throw new GeneralSecurityException("Verification key requires biometric authentication");
        }
        if (info.getUserAuthenticationValidityDurationSeconds() > 0) {
            // The verification key has no stored credentials to migrate.
            keyStore.deleteEntry(AUTH_KEY_ALIAS);
            return generateCredentialKey(AUTH_KEY_ALIAS, true);
        }
        return key;
    }

    private void deleteSecretKey() throws GeneralSecurityException, IOException {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            keyStore.deleteEntry(AUTH_KEY_ALIAS);
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            throw new GeneralSecurityException("Failed to delete biometric auth key", e);
        }
    }

    private boolean validateCryptoObject(BiometricPrompt.AuthenticationResult result) {
        BiometricPrompt.CryptoObject cryptoObject = result.getCryptoObject();
        if (cryptoObject == null || cryptoObject.getCipher() == null) {
            return false;
        }
        if (promptState.authCipher != null && cryptoObject.getCipher() != promptState.authCipher) {
            return false;
        }
        try {
            cryptoObject.getCipher().doFinal(new byte[] { 0x00 });
            return true;
        } catch (GeneralSecurityException | IllegalStateException e) {
            return false;
        }
    }

    private SecretKey generateCredentialKey(String alias, boolean invalidateOnEnrollment) throws GeneralSecurityException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
        } else {
            // CryptoObject requires authentication for every use on Android versions before API 30.
            builder.setUserAuthenticationValidityDurationSeconds(-1);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            builder.setInvalidatedByBiometricEnrollment(invalidateOnEnrollment);
        }

        keyGenerator.init(builder.build());
        return keyGenerator.generateKey();
    }

    private BiometricPrompt.CryptoObject createCredentialEncryptCryptoObject() {
        try {
            promptState.accessControl = getIntent().getIntExtra("accessControl", BIOMETRY_ANY) == BIOMETRY_CURRENT_SET
                ? BIOMETRY_CURRENT_SET
                : BIOMETRY_ANY;
            SharedPreferences prefs = getSharedPreferences(SHARED_PREFS_NAME, MODE_PRIVATE);
            synchronized (ProtectedCredentialStore.LOCK) {
                promptState.writeToken = ProtectedCredentialStore.beginWrite(credentialServer);
                KeyStore keys = KeyStore.getInstance("AndroidKeyStore");
                keys.load(null);
                promptState.credentialAlias = ProtectedCredentialStore.readAlias(prefs, credentialServer);
                promptState.encryptedCredentials = prefs.getString(ProtectedCredentialStore.dataPreference(credentialServer), null);
                promptState.previousAccessControl = prefs.getInt(
                    ProtectedCredentialStore.policyPreference(credentialServer),
                    UNKNOWN_ACCESS_CONTROL
                );
                if (promptState.encryptedCredentials != null && promptState.previousAccessControl == promptState.accessControl) {
                    try {
                        SecretKey key = findCredentialKey(keys, promptState.credentialAlias);
                        if (key != null) {
                            KeyInfo info = getKeyInfo(key);
                            if (isPerUseBiometricKey(info)) {
                                promptState.credentialCipher = initCredentialCipher(Cipher.ENCRYPT_MODE, key);
                                return new BiometricPrompt.CryptoObject(promptState.credentialCipher);
                            }
                        }
                    } catch (UnrecoverableKeyException | KeyPermanentlyInvalidatedException e) {
                        // A replacement can be staged without removing the existing record.
                    }
                }
                promptState.replacementAlias = ProtectedCredentialStore.newAlias(keys, prefs);
                promptState.credentialCipher = initCredentialCipher(
                    Cipher.ENCRYPT_MODE,
                    generateCredentialKey(promptState.replacementAlias, promptState.accessControl == BIOMETRY_CURRENT_SET)
                );
                return new BiometricPrompt.CryptoObject(promptState.credentialCipher);
            }
        } catch (UserNotAuthenticatedException e) {
            finishActivity("error", 10, "Biometric authentication required");
            return null;
        } catch (GeneralSecurityException | IOException | ProviderException | IllegalStateException e) {
            return null;
        }
    }

    /** Looks up an alias in a loaded keystore. */
    static SecretKey findCredentialKey(KeyStore keyStore, String alias) throws GeneralSecurityException {
        Key key = keyStore.getKey(alias, null);
        return key instanceof SecretKey ? (SecretKey) key : null;
    }

    private KeyInfo getKeyInfo(SecretKey key) throws GeneralSecurityException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
        return (KeyInfo) factory.getKeySpec(key, KeyInfo.class);
    }

    private boolean isPerUseBiometricKey(KeyInfo info) {
        return (
            info.isUserAuthenticationRequired() &&
            info.getUserAuthenticationValidityDurationSeconds() <= 0 &&
            (Build.VERSION.SDK_INT < Build.VERSION_CODES.R || info.getUserAuthenticationType() == KeyProperties.AUTH_BIOMETRIC_STRONG)
        );
    }

    private BiometricPrompt.CryptoObject createCredentialDecryptCryptoObject() {
        try {
            SharedPreferences prefs = getSharedPreferences(SHARED_PREFS_NAME, MODE_PRIVATE);
            synchronized (ProtectedCredentialStore.LOCK) {
                promptState.credentialAlias = ProtectedCredentialStore.readAlias(prefs, credentialServer);
                promptState.encryptedCredentials = prefs.getString(ProtectedCredentialStore.dataPreference(credentialServer), null);
                if (promptState.encryptedCredentials == null) {
                    finishActivity("error", NO_PROTECTED_CREDENTIALS, "No protected credentials found");
                    return null;
                }
                KeyStore keys = KeyStore.getInstance("AndroidKeyStore");
                keys.load(null);
                SecretKey key = findCredentialKey(keys, promptState.credentialAlias);
                if (key == null) {
                    finishActivity("error", NO_PROTECTED_CREDENTIALS, "No protected credentials found");
                    return null;
                }

                KeyInfo info = getKeyInfo(key);
                if (!info.isUserAuthenticationRequired()) {
                    finishActivity("error", NO_PROTECTED_CREDENTIALS, "Credential key does not require authentication");
                    return null;
                }
                if (info.getUserAuthenticationValidityDurationSeconds() > 0) {
                    // A legacy key is usable only while the original authentication window is open.
                    promptState.credentialKeyAwaitingAuthentication = key;
                    return null;
                }
                if (!isPerUseBiometricKey(info)) {
                    finishActivity("error", NO_PROTECTED_CREDENTIALS, "Credential key does not support biometric authentication");
                    return null;
                }
                promptState.credentialCipher = initCredentialCipher(Cipher.DECRYPT_MODE, key);
                return new BiometricPrompt.CryptoObject(promptState.credentialCipher);
            }
        } catch (UserNotAuthenticatedException e) {
            finishActivity("error", 10, "Biometric authentication required");
            return null;
        } catch (KeyPermanentlyInvalidatedException e) {
            finishActivity("error", NO_PROTECTED_CREDENTIALS, "Protected credential key invalidated");
            return null;
        } catch (GeneralSecurityException | IOException | ProviderException | IllegalStateException e) {
            return null;
        }
    }

    private Cipher initCredentialCipher(int cipherMode, SecretKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(AUTH_TRANSFORMATION);
        if (cipherMode == Cipher.ENCRYPT_MODE) {
            cipher.init(cipherMode, key);
        } else {
            byte[] combined;
            try {
                combined = Base64.decode(promptState.encryptedCredentials, Base64.DEFAULT);
            } catch (IllegalArgumentException e) {
                throw new GeneralSecurityException("Invalid protected credential data", e);
            }
            if (combined.length < CREDENTIAL_GCM_IV_LENGTH + GCM_TAG_LENGTH_BITS / Byte.SIZE) {
                throw new GeneralSecurityException("Invalid protected credential data");
            }
            cipher.init(cipherMode, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, combined, 0, CREDENTIAL_GCM_IV_LENGTH));
        }
        return cipher;
    }

    private void completeCredentialOperation(BiometricPrompt.AuthenticationResult result) {
        if ("setSecureCredentials".equals(mode)) {
            if (hasPreparedCipher(result)) {
                handleSetSecureCredentials(promptState.credentialCipher);
            }
            return;
        }

        synchronized (ProtectedCredentialStore.LOCK) {
            SharedPreferences prefs = getSharedPreferences(SHARED_PREFS_NAME, MODE_PRIVATE);
            if (!ProtectedCredentialStore.matches(prefs, credentialServer, promptState.credentialAlias, promptState.encryptedCredentials)) {
                finishActivity("error", 10, "Protected credentials changed during authentication");
                return;
            }
            if (promptState.credentialKeyAwaitingAuthentication == null) {
                if (hasPreparedCipher(result)) {
                    handleGetSecureCredentials(promptState.credentialCipher);
                }
                return;
            }

            try {
                handleGetSecureCredentials(initCredentialCipher(Cipher.DECRYPT_MODE, promptState.credentialKeyAwaitingAuthentication));
            } catch (UserNotAuthenticatedException e) {
                finishActivity("error", 10, "Biometric authentication required");
            } catch (KeyPermanentlyInvalidatedException e) {
                finishActivity("error", NO_PROTECTED_CREDENTIALS, "Protected credential key invalidated");
            } catch (GeneralSecurityException | ProviderException e) {
                finishActivity("error", 0, "Biometric crypto object unavailable");
            }
        }
    }

    private boolean hasPreparedCipher(BiometricPrompt.AuthenticationResult result) {
        BiometricPrompt.CryptoObject cryptoObject = result.getCryptoObject();
        if (promptState.credentialCipher == null || cryptoObject == null || cryptoObject.getCipher() != promptState.credentialCipher) {
            finishActivity("error", 10, "Biometric security check failed");
            return false;
        }
        return true;
    }

    private void finishCredentialWrite() {
        if (promptState.writeToken == null) return;
        synchronized (ProtectedCredentialStore.LOCK) {
            ProtectedCredentialStore.finishWrite(credentialServer, promptState.writeToken);
            promptState.writeToken = null;
            if (promptState.replacementAlias != null) {
                deleteUnusedKey(promptState.replacementAlias);
                promptState.replacementAlias = null;
            }
        }
    }

    private void deleteUnusedKey(String alias) {
        synchronized (ProtectedCredentialStore.LOCK) {
            try {
                KeyStore keys = KeyStore.getInstance("AndroidKeyStore");
                keys.load(null);
                ProtectedCredentialStore.deleteProtectedKey(keys, getSharedPreferences(SHARED_PREFS_NAME, MODE_PRIVATE), alias);
            } catch (GeneralSecurityException | IOException | ProviderException e) {
                Log.w("NativeBiometric", "Could not remove an unused biometric key", e);
            }
        }
    }

    private void handleSetSecureCredentials(Cipher cipher) {
        try {
            String username = getIntent().getStringExtra("username");
            String password = getIntent().getStringExtra("password");
            String server = getIntent().getStringExtra("server");

            JSONObject json = new JSONObject();
            json.put("u", username);
            json.put("p", password);

            byte[] encrypted = cipher.doFinal(json.toString().getBytes(StandardCharsets.UTF_8));
            byte[] iv = cipher.getIV();

            byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

            String encoded = Base64.encodeToString(combined, Base64.DEFAULT);

            SharedPreferences prefs = getSharedPreferences(SHARED_PREFS_NAME, MODE_PRIVATE);
            synchronized (ProtectedCredentialStore.LOCK) {
                if (
                    !ProtectedCredentialStore.isCurrentWrite(server, promptState.writeToken) ||
                    !ProtectedCredentialStore.matches(prefs, server, promptState.credentialAlias, promptState.encryptedCredentials)
                ) {
                    finishActivity("error", 10, "Protected credentials changed during authentication");
                    return;
                }
                SharedPreferences.Editor editor = prefs.edit().putString(ProtectedCredentialStore.dataPreference(server), encoded);
                if (promptState.replacementAlias == null) {
                    editor.apply();
                } else {
                    String alias = promptState.replacementAlias;
                    promptState.replacementAlias = null;
                    // Keep both keys if the write fails. The record may already be visible in memory.
                    if (
                        !editor
                            .putString(ProtectedCredentialStore.aliasPreference(server), alias)
                            .putInt(ProtectedCredentialStore.policyPreference(server), promptState.accessControl)
                            .commit()
                    ) {
                        SharedPreferences.Editor rollback = prefs
                            .edit()
                            .putString(ProtectedCredentialStore.dataPreference(server), promptState.encryptedCredentials)
                            .putString(ProtectedCredentialStore.aliasPreference(server), promptState.credentialAlias);
                        if (promptState.previousAccessControl == UNKNOWN_ACCESS_CONTROL) {
                            rollback.remove(ProtectedCredentialStore.policyPreference(server));
                        } else {
                            rollback.putInt(ProtectedCredentialStore.policyPreference(server), promptState.previousAccessControl);
                        }
                        rollback.apply();
                        finishActivity("error", 0, "Failed to persist protected credentials");
                        return;
                    }
                    deleteUnusedKey(promptState.credentialAlias);
                }
            }
            finishActivity();
        } catch (Exception e) {
            finishActivity("error", 0, "Failed to encrypt credentials: " + e.getMessage());
        }
    }

    private void handleGetSecureCredentials(Cipher cipher) {
        try {
            byte[] combined = Base64.decode(promptState.encryptedCredentials, Base64.DEFAULT);
            byte[] ciphertext = new byte[combined.length - CREDENTIAL_GCM_IV_LENGTH];
            System.arraycopy(combined, CREDENTIAL_GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);

            byte[] decrypted = cipher.doFinal(ciphertext);
            String jsonStr = new String(decrypted, StandardCharsets.UTF_8);
            JSONObject json = new JSONObject(jsonStr);

            Intent intent = activityResult();
            intent.putExtra("result", "success");
            intent.putExtra("username", json.getString("u"));
            intent.putExtra("password", json.getString("p"));
            activityFinished = true;
            setResult(RESULT_OK, intent);
            finish();
        } catch (AEADBadTagException e) {
            finishActivity("error", NO_PROTECTED_CREDENTIALS, "Protected credentials could not be recovered");
        } catch (Exception e) {
            finishActivity("error", 0, "Failed to decrypt credentials: " + e.getMessage());
        }
    }

    /**
     * Convert Auth Error Codes to plugin expected Biometric Auth Errors (in README.md)
     * This way both iOS and Android return the same error codes for the same authentication failure reasons.
     * !!IMPORTANT!!: Whenever this is modified, check if similar function in iOS Plugin.swift needs to be modified as well
     * @see <a href="https://developer.android.com/reference/androidx/biometric/BiometricPrompt#constants">...</a>
     * @return BiometricAuthError
     */
    public static int convertToPluginErrorCode(int errorCode) {
        switch (errorCode) {
            case BiometricPrompt.ERROR_HW_UNAVAILABLE:
            case BiometricPrompt.ERROR_HW_NOT_PRESENT:
                return 1;
            case BiometricPrompt.ERROR_LOCKOUT_PERMANENT:
                return 2; // Permanent lockout
            case BiometricPrompt.ERROR_NO_BIOMETRICS:
                return 3;
            case BiometricPrompt.ERROR_LOCKOUT:
                return 4; // Temporary lockout (too many attempts)
            // Authentication Failure (10) Handled by `onAuthenticationFailed`.
            // App Cancel (11), Invalid Context (12), and Not Interactive (13) are not valid error codes for Android.
            case BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL:
                return 14;
            case BiometricPrompt.ERROR_TIMEOUT:
            case BiometricPrompt.ERROR_CANCELED:
                return 15;
            case BiometricPrompt.ERROR_USER_CANCELED:
            case BiometricPrompt.ERROR_NEGATIVE_BUTTON:
                return 16;
            case BiometricPrompt.AUTHENTICATION_RESULT_TYPE_BIOMETRIC:
                return 0; // Success case, should not be handled here
            default:
                return 0;
        }
    }

    /**
     * Maps supported Android biometry types to a prompt mask. A list with no Android types uses
     * strong biometrics. Implicit device credential fallback is added on Android 11 and newer.
     */
    static int resolvePromptAuthenticators(int[] allowedTypes, boolean useFallback, int sdkVersion) {
        int authenticators = allowedTypes == null
            ? BiometricManager.Authenticators.BIOMETRIC_STRONG
            : getAllowedAuthenticators(allowedTypes);
        if (useFallback && sdkVersion >= Build.VERSION_CODES.R) {
            authenticators |= BiometricManager.Authenticators.DEVICE_CREDENTIAL;
        }
        return authenticators;
    }

    /** Checks only the device credential bit. PromptInfo validates support on the running Android version. */
    static boolean allowsDeviceCredential(int authenticators) {
        return (authenticators & BiometricManager.Authenticators.DEVICE_CREDENTIAL) != 0;
    }

    private static int getAllowedAuthenticators(int[] allowedTypes) {
        int authenticators = 0;
        for (int type : allowedTypes) {
            switch (type) {
                case 3: // FINGERPRINT
                    authenticators |= BiometricManager.Authenticators.BIOMETRIC_STRONG;
                    break;
                case 4: // FACE_AUTHENTICATION
                    authenticators |= BiometricManager.Authenticators.BIOMETRIC_STRONG;
                    break;
                case 5: // IRIS_AUTHENTICATION
                    authenticators |= BiometricManager.Authenticators.BIOMETRIC_STRONG;
                    break;
                case 6: // MULTIPLE - allow all biometric types
                    authenticators |= BiometricManager.Authenticators.BIOMETRIC_STRONG;
                    break;
                case 7: // DEVICE_CREDENTIAL (PIN, pattern, or password)
                    authenticators |= BiometricManager.Authenticators.DEVICE_CREDENTIAL;
                    break;
            }
        }
        return authenticators > 0 ? authenticators : BiometricManager.Authenticators.BIOMETRIC_STRONG;
    }
}
