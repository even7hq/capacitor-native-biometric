package ee.forgr.biometric;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.os.Build;
import androidx.biometric.BiometricManager;
import java.security.KeyStore;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.junit.Test;

public class AuthActivityTest {

    @Test
    public void fallbackKeepsCancelOnAndroid10() {
        int authenticators = AuthActivity.resolvePromptAuthenticators(null, true, Build.VERSION_CODES.Q);

        assertEquals(BiometricManager.Authenticators.BIOMETRIC_STRONG, authenticators);
        assertFalse(AuthActivity.allowsDeviceCredential(authenticators));
    }

    @Test
    public void fallbackOffersDeviceCredentialOnAndroid11() {
        int authenticators = AuthActivity.resolvePromptAuthenticators(null, true, Build.VERSION_CODES.R);

        assertEquals(BiometricManager.Authenticators.BIOMETRIC_STRONG | BiometricManager.Authenticators.DEVICE_CREDENTIAL, authenticators);
        assertTrue(AuthActivity.allowsDeviceCredential(authenticators));
    }

    @Test
    public void readingAnAbsentCredentialKeyDoesNotCreateAnAlias() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null);

        assertNull(AuthActivity.findCredentialKey(keyStore, "test", "payload"));
        assertEquals(0, keyStore.size());
    }

    @Test
    public void readingAnExistingCredentialKeyUsesTheStoredKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null);
        SecretKey existing = KeyGenerator.getInstance("AES").generateKey();
        keyStore.setEntry(
            "NativeBiometricSecure_test",
            new KeyStore.SecretKeyEntry(existing),
            new KeyStore.PasswordProtection(new char[0])
        );

        assertArrayEquals(existing.getEncoded(), AuthActivity.findCredentialKey(keyStore, "test", "payload").getEncoded());
        assertEquals(1, keyStore.size());
    }

    @Test
    public void replacementKeyIsUsedOnlyAfterItsPayloadIsStored() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null);
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecretKey legacy = keyGenerator.generateKey();
        SecretKey replacement = keyGenerator.generateKey();
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(new char[0]);
        keyStore.setEntry("NativeBiometricSecure_test", new KeyStore.SecretKeyEntry(legacy), protection);
        keyStore.setEntry("NativeBiometricPerUse_test", new KeyStore.SecretKeyEntry(replacement), protection);

        assertArrayEquals(legacy.getEncoded(), AuthActivity.findCredentialKey(keyStore, "test", "old").getEncoded());
        assertArrayEquals(replacement.getEncoded(), AuthActivity.findCredentialKey(keyStore, "test", "per-use:new").getEncoded());
        assertEquals(2, keyStore.size());

        AuthActivity.deleteCredentialKeys(keyStore, "test");
        assertEquals(0, keyStore.size());
    }
}
