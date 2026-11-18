package ee.forgr.biometric;

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
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import ee.forgr.biometric.capacitornativebiometric.R;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
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
    static final String SECURE_KEY_PREFIX = "NativeBiometricSecure_";
    private static final int CREDENTIAL_GCM_IV_LENGTH = 12;
    private static final String SHARED_PREFS_NAME = "NativeBiometricSharedPreferences";
    private static final int NO_PROTECTED_CREDENTIALS = 21;

    private BiometricPrompt biometricPrompt;
    private Cipher authCipher;
    private SecretKey credentialKeyAwaitingAuthentication;
    private String encryptedCredentials;
    private String mode;
    private int maxAttempts;
    private int counter = 0;
    private boolean activityFinished = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_auth_acitivy);

        mode = getIntent().getStringExtra("mode");
        if (mode == null) mode = "verify";

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

        boolean verifyWithoutCrypto = verify && (useFallback || deviceCredentialAllowed);
        BiometricPrompt.PromptInfo promptInfo;
        try {
            promptInfo = builder.build();
        } catch (IllegalArgumentException e) {
            finishActivity("error", 0, "Invalid biometric prompt configuration");
            return;
        }

        biometricPrompt = new BiometricPrompt(
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
                    counter++;
                    if (counter >= maxAttempts) {
                        // Do NOT call cancelAuthentication() here, it triggers onAuthenticationError(ERROR_CANCELED)
                        // which would call finishActivity again, overwriting our result.
                        // finish() alone closes the Activity and dismisses the BiometricPrompt automatically.
                        // We cannot use error code 4 here; it is reserved for Android system lockout (30s) from onAuthenticationError.
                        finishActivity("error", 10, "Authentication Failed");
                    }
                }
            }
        );

        // The identity prompt can verify the user without unlocking a protected credential.
        if (verifyWithoutCrypto) {
            biometricPrompt.authenticate(promptInfo);
            return;
        }

        BiometricPrompt.CryptoObject cryptoObject;
        if ("setSecureCredentials".equals(mode)) {
            cryptoObject = createCredentialEncryptCryptoObject();
        } else if ("getSecureCredentials".equals(mode)) {
            cryptoObject = createCredentialDecryptCryptoObject();
        } else {
            cryptoObject = createCryptoObject();
        }
        if (credentialKeyAwaitingAuthentication != null) {
            biometricPrompt.authenticate(promptInfo);
        } else if (cryptoObject != null) {
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

        Intent intent = new Intent();
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

    private BiometricPrompt.CryptoObject createCryptoObject() {
        try {
            authCipher = createCipher();
            return new BiometricPrompt.CryptoObject(authCipher);
        } catch (GeneralSecurityException | IOException e) {
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
        if (!keyStore.containsAlias(AUTH_KEY_ALIAS)) {
            generateSecretKey();
        }
        try {
            return (SecretKey) keyStore.getKey(AUTH_KEY_ALIAS, null);
        } catch (UnrecoverableKeyException e) {
            throw new GeneralSecurityException("Failed to retrieve biometric auth key", e);
        }
    }

    private void generateSecretKey() throws GeneralSecurityException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
            AUTH_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
        } else {
            builder.setUserAuthenticationValidityDurationSeconds(1);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setInvalidatedByBiometricEnrollment(true);
        }

        keyGenerator.init(builder.build());
        keyGenerator.generateKey();
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
        if (authCipher != null && cryptoObject.getCipher() != authCipher) {
            return false;
        }
        try {
            cryptoObject.getCipher().doFinal(new byte[] { 0x00 });
            return true;
        } catch (GeneralSecurityException | IllegalStateException e) {
            return false;
        }
    }

    private SecretKey getOrCreateCredentialKey(KeyStore keyStore, String alias, int accessControl) throws GeneralSecurityException {
        Key existingKey = keyStore.getKey(alias, null);
        if (existingKey instanceof SecretKey) {
            return (SecretKey) existingKey;
        }

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
            builder.setInvalidatedByBiometricEnrollment(accessControl == 1);
        }

        keyGenerator.init(builder.build());
        return keyGenerator.generateKey();
    }

    private BiometricPrompt.CryptoObject createCredentialEncryptCryptoObject() {
        try {
            String server = getIntent().getStringExtra("server");
            int accessControl = getIntent().getIntExtra("accessControl", 2);
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            String alias = SECURE_KEY_PREFIX + server;
            SecretKey key = getOrCreateCredentialKey(keyStore, alias, accessControl);
            try {
                return prepareCredentialCryptoObject(Cipher.ENCRYPT_MODE, key);
            } catch (KeyPermanentlyInvalidatedException e) {
                keyStore.deleteEntry(alias);
                return prepareCredentialCryptoObject(Cipher.ENCRYPT_MODE, getOrCreateCredentialKey(keyStore, alias, accessControl));
            }
        } catch (UserNotAuthenticatedException e) {
            finishActivity("error", 10, "Biometric authentication required");
            return null;
        } catch (GeneralSecurityException | IOException e) {
            return null;
        }
    }

    /** Looks up a protected credential in a loaded keystore without creating or replacing any alias. */
    static SecretKey findCredentialKey(KeyStore keyStore, String server) throws GeneralSecurityException {
        Key key = keyStore.getKey(SECURE_KEY_PREFIX + server, null);
        return key instanceof SecretKey ? (SecretKey) key : null;
    }

    private BiometricPrompt.CryptoObject createCredentialDecryptCryptoObject() {
        try {
            String server = getIntent().getStringExtra("server");
            SharedPreferences prefs = getSharedPreferences(SHARED_PREFS_NAME, MODE_PRIVATE);
            encryptedCredentials = prefs.getString("secure_" + server, null);
            if (encryptedCredentials == null) {
                finishActivity("error", NO_PROTECTED_CREDENTIALS, "No protected credentials found");
                return null;
            }

            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            SecretKey key = findCredentialKey(keyStore, server);
            if (key == null) {
                finishActivity("error", NO_PROTECTED_CREDENTIALS, "No protected credentials found");
                return null;
            }

            return prepareCredentialCryptoObject(Cipher.DECRYPT_MODE, key);
        } catch (UserNotAuthenticatedException e) {
            finishActivity("error", 10, "Biometric authentication required");
            return null;
        } catch (InvalidKeyException | UnrecoverableKeyException e) {
            finishActivity("error", NO_PROTECTED_CREDENTIALS, "Protected credentials could not be recovered");
            return null;
        } catch (GeneralSecurityException | IOException e) {
            return null;
        }
    }

    private BiometricPrompt.CryptoObject prepareCredentialCryptoObject(int cipherMode, SecretKey key) throws GeneralSecurityException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
        KeyInfo info = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);
        if (info.getUserAuthenticationValidityDurationSeconds() > 0) {
            // Preserve the old key and authenticate before initializing a time-window cipher.
            credentialKeyAwaitingAuthentication = key;
            return null;
        }
        return new BiometricPrompt.CryptoObject(initCredentialCipher(cipherMode, key));
    }

    private Cipher initCredentialCipher(int cipherMode, SecretKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(AUTH_TRANSFORMATION);
        if (cipherMode == Cipher.ENCRYPT_MODE) {
            cipher.init(cipherMode, key);
        } else {
            byte[] combined = Base64.decode(encryptedCredentials, Base64.DEFAULT);
            cipher.init(cipherMode, key, new GCMParameterSpec(128, combined, 0, CREDENTIAL_GCM_IV_LENGTH));
        }
        return cipher;
    }

    private void completeCredentialOperation(BiometricPrompt.AuthenticationResult result) {
        boolean writing = "setSecureCredentials".equals(mode);
        Cipher cipher;
        if (credentialKeyAwaitingAuthentication != null) {
            try {
                // Initialize and use the original key immediately, within its authentication window.
                cipher = initCredentialCipher(writing ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, credentialKeyAwaitingAuthentication);
            } catch (UserNotAuthenticatedException e) {
                finishActivity("error", 10, "Biometric authentication required");
                return;
            } catch (InvalidKeyException e) {
                finishActivity("error", writing ? 0 : NO_PROTECTED_CREDENTIALS, "Protected credential key unavailable");
                return;
            } catch (GeneralSecurityException e) {
                finishActivity("error", 0, "Biometric crypto object unavailable");
                return;
            }
        } else {
            BiometricPrompt.CryptoObject cryptoObject = result.getCryptoObject();
            if (cryptoObject == null || cryptoObject.getCipher() == null) {
                finishActivity("error", 10, "Biometric security check failed");
                return;
            }
            cipher = cryptoObject.getCipher();
        }

        if (writing) {
            handleSetSecureCredentials(cipher);
        } else {
            handleGetSecureCredentials(cipher);
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

            SharedPreferences.Editor editor = getSharedPreferences(SHARED_PREFS_NAME, MODE_PRIVATE).edit();
            editor.putString("secure_" + server, encoded);
            editor.apply();

            finishActivity();
        } catch (Exception e) {
            finishActivity("error", 0, "Failed to encrypt credentials: " + e.getMessage());
        }
    }

    private void handleGetSecureCredentials(Cipher cipher) {
        try {
            String server = getIntent().getStringExtra("server");

            SharedPreferences prefs = getSharedPreferences(SHARED_PREFS_NAME, MODE_PRIVATE);
            String encryptedData = prefs.getString("secure_" + server, null);
            if (encryptedData == null) {
                finishActivity("error", NO_PROTECTED_CREDENTIALS, "No protected credentials found");
                return;
            }

            if (!encryptedData.equals(encryptedCredentials)) {
                finishActivity("error", 10, "Protected credentials changed during authentication");
                return;
            }

            byte[] combined = Base64.decode(encryptedCredentials, Base64.DEFAULT);
            byte[] ciphertext = new byte[combined.length - CREDENTIAL_GCM_IV_LENGTH];
            System.arraycopy(combined, CREDENTIAL_GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);

            byte[] decrypted = cipher.doFinal(ciphertext);
            String jsonStr = new String(decrypted, StandardCharsets.UTF_8);
            JSONObject json = new JSONObject(jsonStr);

            Intent intent = new Intent();
            intent.putExtra("result", "success");
            intent.putExtra("username", json.getString("u"));
            intent.putExtra("password", json.getString("p"));
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
