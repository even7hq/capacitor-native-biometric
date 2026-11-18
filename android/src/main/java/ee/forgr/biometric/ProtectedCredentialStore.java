package ee.forgr.biometric;

import android.content.SharedPreferences;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

final class ProtectedCredentialStore {

    static final Object LOCK = new Object();
    private static final Map<String, Object> writes = new HashMap<>();
    static final String LEGACY_KEY_PREFIX = "NativeBiometricSecure_";
    private static final String REPLACEMENT_KEY_PREFIX = "NativeBiometricProtected_";

    private ProtectedCredentialStore() {}

    // Access to the pending writes is serialized with credential preference and key mutations.
    static Object beginWrite(String server) {
        Object token = new Object();
        writes.put(server, token);
        return token;
    }

    static boolean isCurrentWrite(String server, Object token) {
        return writes.get(server) == token;
    }

    static void finishWrite(String server, Object token) {
        writes.remove(server, token);
    }

    static void cancelWrite(String server) {
        writes.remove(server);
    }

    static String dataPreference(String server) {
        return "secure_" + server;
    }

    static String aliasPreference(String server) {
        // The final colon keeps this key separate from the username and password preferences.
        return "protected-alias:" + server + ":";
    }

    static String policyPreference(String server) {
        return "protected-policy:" + server + ":";
    }

    static String readAlias(SharedPreferences prefs, String server) {
        return prefs.getString(aliasPreference(server), LEGACY_KEY_PREFIX + server);
    }

    static boolean hasRawCredentials(SharedPreferences prefs, String alias) {
        return prefs.contains(alias + "-username") || prefs.contains(alias + "-password");
    }

    static boolean isReplacementAlias(String alias) {
        return alias.startsWith(REPLACEMENT_KEY_PREFIX);
    }

    static String newAlias(KeyStore keys, SharedPreferences prefs) throws KeyStoreException {
        String alias;
        do {
            alias = REPLACEMENT_KEY_PREFIX + UUID.randomUUID();
        } while (keys.containsAlias(alias) || hasRawCredentials(prefs, alias));
        return alias;
    }

    static boolean matches(SharedPreferences prefs, String server, String alias, String data) {
        return alias.equals(readAlias(prefs, server)) && Objects.equals(data, prefs.getString(dataPreference(server), null));
    }

    static void deleteProtectedKey(KeyStore keys, SharedPreferences prefs, String alias) throws KeyStoreException {
        if (!hasRawCredentials(prefs, alias)) {
            keys.deleteEntry(alias);
        }
    }
}
