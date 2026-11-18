package ee.forgr.biometric;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import android.content.SharedPreferences;
import android.os.Build;
import androidx.biometric.BiometricManager;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;
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

        assertNull(AuthActivity.findCredentialKey(keyStore, ProtectedCredentialStore.LEGACY_KEY_PREFIX + "test"));
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

        assertArrayEquals(
            existing.getEncoded(),
            AuthActivity.findCredentialKey(keyStore, ProtectedCredentialStore.LEGACY_KEY_PREFIX + "test").getEncoded()
        );
        assertEquals(1, keyStore.size());
    }

    @Test
    public void deletingCredentialsPreservesAnotherServersRawKey() throws Exception {
        String otherAlias = ProtectedCredentialStore.LEGACY_KEY_PREFIX + "test";
        KeyStore keyStore = keyStoreWithKeys("test", otherAlias);

        NativeBiometric.deleteCredentialKeys(
            keyStore,
            preferencesWith(Map.of(otherAlias + "-username", "one", otherAlias + "-password", "two")),
            "test"
        );

        assertFalse(keyStore.containsAlias("test"));
        assertTrue(keyStore.containsAlias(otherAlias));
    }

    @Test
    public void deletingCredentialsPreservesAnotherServersProtectedKey() throws Exception {
        String otherAlias = ProtectedCredentialStore.LEGACY_KEY_PREFIX + "test";
        KeyStore keyStore = keyStoreWithKeys(otherAlias, ProtectedCredentialStore.LEGACY_KEY_PREFIX + otherAlias);

        NativeBiometric.deleteCredentialKeys(keyStore, preferencesWith(Map.of("secure_test", "previous")), otherAlias);

        assertTrue(keyStore.containsAlias(otherAlias));
        assertFalse(keyStore.containsAlias(ProtectedCredentialStore.LEGACY_KEY_PREFIX + otherAlias));
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

    @Test
    public void deletingCredentialsKeepsUnrelatedReplacementKeys() throws Exception {
        String replacementAlias = "NativeBiometricProtected_example";
        KeyStore keyStore = keyStoreWithKeys(replacementAlias);
        SharedPreferences prefs = preferencesWith(
            Map.of(
                ProtectedCredentialStore.aliasPreference("owner"),
                replacementAlias,
                ProtectedCredentialStore.policyPreference("owner"),
                "policy",
                "secure_owner",
                "encrypted data"
            )
        );

        NativeBiometric.deleteCredentialKeys(keyStore, prefs, replacementAlias);
        assertTrue(keyStore.containsAlias(replacementAlias));

        NativeBiometric.deleteCredentialKeys(keyStore, prefs, "owner");
        assertFalse(keyStore.containsAlias(replacementAlias));
        assertFalse(prefs.contains(ProtectedCredentialStore.aliasPreference("owner")));
        assertFalse(prefs.contains(ProtectedCredentialStore.policyPreference("owner")));
        assertFalse(prefs.contains("secure_owner"));
    }

    @Test
    public void deletingCredentialsRemovesAnAbandonedRawKeyWithTheProtectedPrefix() throws Exception {
        String alias = "NativeBiometricProtected_abandoned";
        KeyStore keyStore = keyStoreWithKeys(alias);
        SharedPreferences prefs = preferencesWith(Map.of());

        assertFalse(ProtectedCredentialStore.isProtectedReplacementAlias(prefs, alias));
        NativeBiometric.deleteCredentialKeys(keyStore, prefs, alias);
        assertFalse(keyStore.containsAlias(alias));
    }

    @Test
    public void recoveryRemovesAnAbandonedStagedKeyAndKeepsTheCurrentRecord() throws Exception {
        String server = "owner";
        String active = "NativeBiometricProtected_active";
        String staged = "NativeBiometricProtected_staged";
        KeyStore keyStore = keyStoreWithKeys(active, staged);
        SharedPreferences prefs = preferencesWith(Map.of(ProtectedCredentialStore.aliasPreference(server), active, "secure_owner", "data"));

        ProtectedCredentialStore.persistPendingAlias(prefs, server, staged);
        assertTrue(ProtectedCredentialStore.isProtectedReplacementAlias(prefs, staged));
        NativeBiometric.deleteCredentialKeys(keyStore, prefs, staged);
        assertTrue(keyStore.containsAlias(staged));

        ProtectedCredentialStore.reconcilePendingAlias(keyStore, prefs, server, staged, false);
        assertTrue(keyStore.containsAlias(active));
        assertFalse(keyStore.containsAlias(staged));
        assertNull(ProtectedCredentialStore.readPendingAlias(prefs, server));
        assertTrue(ProtectedCredentialStore.matches(prefs, server, active, "data"));
    }

    @Test
    public void recoveryKeepsBothKeysWhenTheCurrentRecordCannotBePersisted() throws Exception {
        String server = "owner";
        String active = "NativeBiometricProtected_active";
        String staged = "NativeBiometricProtected_staged";
        KeyStore keyStore = keyStoreWithKeys(active, staged);
        SharedPreferences prefs = preferencesWith(
            Map.of(
                ProtectedCredentialStore.aliasPreference(server),
                active,
                ProtectedCredentialStore.pendingAliasPreference(server),
                staged
            ),
            false
        );

        assertThrows(IOException.class, () -> ProtectedCredentialStore.reconcilePendingAlias(keyStore, prefs, server, staged, false));
        assertEquals(staged, ProtectedCredentialStore.readPendingAlias(prefs, server));
        assertTrue(ProtectedCredentialStore.isProtectedReplacementAlias(prefs, staged));
        assertTrue(keyStore.containsAlias(active));
        assertTrue(keyStore.containsAlias(staged));
    }

    @Test
    public void deletingRawCredentialsRemovesTheirKeyAfterAnotherServerHasMigrated() throws Exception {
        String otherAlias = "NativeBiometricProtected_other";
        String rawServer = ProtectedCredentialStore.LEGACY_KEY_PREFIX + "owner";
        KeyStore keyStore = keyStoreWithKeys(rawServer, otherAlias);
        SharedPreferences prefs = preferencesWith(
            Map.of(
                ProtectedCredentialStore.aliasPreference("owner"),
                otherAlias,
                "secure_owner",
                "encrypted data",
                rawServer + "-username",
                "username",
                rawServer + "-password",
                "password"
            )
        );

        NativeBiometric.deleteCredentialKeys(keyStore, prefs, rawServer);

        assertFalse(keyStore.containsAlias(rawServer));
        assertTrue(keyStore.containsAlias(otherAlias));
        assertTrue(prefs.contains("secure_owner"));
    }

    @Test
    public void recordMustStillPointToTheCipherAndAliasPreparedBeforeAuthentication() {
        String alias = ProtectedCredentialStore.LEGACY_KEY_PREFIX + "test";
        SharedPreferences prefs = preferencesWith(Map.of("secure_test", "previous"));

        assertTrue(ProtectedCredentialStore.matches(prefs, "test", alias, "previous"));
        assertFalse(ProtectedCredentialStore.matches(prefs, "test", alias, "older"));

        prefs.edit().putString(ProtectedCredentialStore.aliasPreference("test"), "replacement").apply();
        assertFalse(ProtectedCredentialStore.matches(prefs, "test", alias, "previous"));
    }

    @Test
    public void supersededOrCancelledWritesCannotReplaceTheCurrentRecord() {
        String server = "pending-credentials";
        synchronized (ProtectedCredentialStore.LOCK) {
            Object first = ProtectedCredentialStore.beginWrite(server);
            Object second = ProtectedCredentialStore.beginWrite(server);
            assertFalse(ProtectedCredentialStore.isCurrentWrite(server, first));
            ProtectedCredentialStore.finishWrite(server, first);
            assertTrue(ProtectedCredentialStore.isCurrentWrite(server, second));

            ProtectedCredentialStore.cancelWrite(server);
            assertFalse(ProtectedCredentialStore.isCurrentWrite(server, second));
        }
    }

    private static SharedPreferences preferencesWith(Map<String, String> initialValues) {
        return preferencesWith(initialValues, true);
    }

    private static SharedPreferences preferencesWith(Map<String, String> initialValues, boolean persists) {
        Map<String, String> values = new HashMap<>(initialValues);
        return (SharedPreferences) Proxy.newProxyInstance(
            SharedPreferences.class.getClassLoader(),
            new Class<?>[] { SharedPreferences.class },
            (proxy, method, arguments) -> {
                switch (method.getName()) {
                    case "contains":
                        return values.containsKey(arguments[0]);
                    case "getString":
                        return values.getOrDefault(arguments[0], (String) arguments[1]);
                    case "getAll":
                        return new HashMap<>(values);
                    case "edit":
                        return edit(values, persists);
                    default:
                        throw new UnsupportedOperationException(method.getName());
                }
            }
        );
    }

    private static SharedPreferences.Editor edit(Map<String, String> values, boolean persists) {
        return (SharedPreferences.Editor) Proxy.newProxyInstance(
            SharedPreferences.Editor.class.getClassLoader(),
            new Class<?>[] { SharedPreferences.Editor.class },
            (proxy, method, arguments) -> {
                switch (method.getName()) {
                    case "remove":
                        values.remove(arguments[0]);
                        return proxy;
                    case "putString":
                        values.put((String) arguments[0], (String) arguments[1]);
                        return proxy;
                    case "apply":
                        return null;
                    case "commit":
                        return persists;
                    default:
                        throw new UnsupportedOperationException(method.getName());
                }
            }
        );
    }
}
