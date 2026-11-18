package ee.forgr.biometric;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import android.content.SharedPreferences;
import android.os.Build;
import androidx.biometric.BiometricManager;
import java.lang.reflect.Proxy;
import java.security.KeyStore;
import java.util.Arrays;
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

        assertNull(AuthActivity.findCredentialKey(keyStore, "test"));
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

        assertArrayEquals(existing.getEncoded(), AuthActivity.findCredentialKey(keyStore, "test").getEncoded());
        assertEquals(1, keyStore.size());
    }

    @Test
    public void deletingCredentialsPreservesAnotherServersRawKey() throws Exception {
        String otherAlias = AuthActivity.SECURE_KEY_PREFIX + "test";
        KeyStore keyStore = keyStoreWithKeys("test", otherAlias);

        NativeBiometric.deleteCredentialKeys(keyStore, preferencesWith(otherAlias + "-username", otherAlias + "-password"), "test");

        assertFalse(keyStore.containsAlias("test"));
        assertTrue(keyStore.containsAlias(otherAlias));
    }

    @Test
    public void deletingCredentialsPreservesAnotherServersProtectedKey() throws Exception {
        String otherAlias = AuthActivity.SECURE_KEY_PREFIX + "test";
        KeyStore keyStore = keyStoreWithKeys(otherAlias, AuthActivity.SECURE_KEY_PREFIX + otherAlias);

        NativeBiometric.deleteCredentialKeys(keyStore, preferencesWith("secure_test"), otherAlias);

        assertTrue(keyStore.containsAlias(otherAlias));
        assertFalse(keyStore.containsAlias(AuthActivity.SECURE_KEY_PREFIX + otherAlias));
    }

    private static KeyStore keyStoreWithKeys(String... aliases) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null);
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(new char[0]);
        for (String alias : aliases) {
            keyStore.setEntry(alias, new KeyStore.SecretKeyEntry(generator.generateKey()), protection);
        }
        return keyStore;
    }

    private static SharedPreferences preferencesWith(String... keys) {
        return (SharedPreferences) Proxy.newProxyInstance(
            SharedPreferences.class.getClassLoader(),
            new Class<?>[] { SharedPreferences.class },
            (proxy, method, arguments) -> {
                if (method.getName().equals("contains")) {
                    return Arrays.asList(keys).contains(arguments[0]);
                }
                throw new UnsupportedOperationException(method.getName());
            }
        );
    }
}
