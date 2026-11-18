package ee.forgr.biometric;

import android.content.SharedPreferences;
import java.io.IOException;
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
    private static final String ALIAS_PREFERENCE_PREFIX = "protected-alias:";
    private static final String PENDING_ALIAS_PREFERENCE_PREFIX = "protected-pending-alias:";
    private static final String PENDING_WRITE_MARKER = ":";

    private ProtectedCredentialStore() {}

    /** The caller holds LOCK while accessing write tokens or changing preferences and keys. */
    static Object beginWrite(String server) {
        Object token = new Object();
        writes.put(server, token);
        return token;
    }

    static boolean isCurrentWrite(String server, Object token) {
        return writes.get(server) == token;
    }

    /** Releases only the supplied write token. */
    static void finishWrite(String server, Object token) {
        writes.remove(server, token);
    }

    /** Invalidates the current write for this server. */
    static void cancelWrite(String server) {
        writes.remove(server);
    }

    static String dataPreference(String server) {
        return "secure_" + server;
    }

    static String aliasPreference(String server) {
        // The final colon keeps this key separate from the username and password preferences.
        return ALIAS_PREFERENCE_PREFIX + server + ":";
    }

    static String pendingAliasPreference(String server) {
        return PENDING_ALIAS_PREFERENCE_PREFIX + server + ":";
    }

    static String readPendingAlias(SharedPreferences prefs, String server) {
        String value = prefs.getString(pendingAliasPreference(server), null);
        return value != null && value.startsWith(PENDING_WRITE_MARKER) ? value.substring(PENDING_WRITE_MARKER.length()) : value;
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

    static boolean isProtectedReplacementAlias(SharedPreferences prefs, String alias) {
        if (!alias.startsWith(REPLACEMENT_KEY_PREFIX)) return false;
        for (Map.Entry<String, ?> entry : prefs.getAll().entrySet()) {
            String preference = entry.getKey();
            Object value = entry.getValue();
            if (
                preference.endsWith(":") &&
                ((preference.startsWith(ALIAS_PREFERENCE_PREFIX) && alias.equals(value)) ||
                    (preference.startsWith(PENDING_ALIAS_PREFERENCE_PREFIX) &&
                        (alias.equals(value) || (PENDING_WRITE_MARKER + alias).equals(value))))
            ) {
                return true;
            }
        }
        return false;
    }

    static void persistPendingAlias(SharedPreferences prefs, String server, String value) throws IOException {
        if (!prefs.edit().putString(pendingAliasPreference(server), value).commit()) {
            throw new IOException("Could not persist the pending biometric key alias");
        }
    }

    /** Reconciles a staged or retired key under LOCK, including after process death. */
    static void reconcilePendingAlias(KeyStore keys, SharedPreferences prefs, String server, String alias, boolean recordPersisted)
        throws KeyStoreException, IOException {
        if (alias == null || !alias.equals(readPendingAlias(prefs, server))) return;
        if (!alias.equals(readAlias(prefs, server))) {
            if (!recordPersisted) {
                // Older Android versions skip disk I/O when a commit repeats the same value.
                String stored = prefs.getString(pendingAliasPreference(server), null);
                persistPendingAlias(prefs, server, alias.equals(stored) ? PENDING_WRITE_MARKER + alias : alias);
            }
            deleteProtectedKey(keys, prefs, alias);
        }
        prefs.edit().remove(pendingAliasPreference(server)).apply();
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
