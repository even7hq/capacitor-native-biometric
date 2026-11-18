package ee.forgr.biometric;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

import org.junit.Test;

public class BiometricActivityRequestsTest {

    @Test
    public void theActivePromptOwnsTheSlotAcrossAllMethods() {
        BiometricActivityRequests requests = new BiometricActivityRequests();
        BiometricActivityRequests.Request first = requests.begin("verifyResult", "verifyIdentity");

        assertNull(requests.begin("getSecureCredentialsResult", "getSecureCredentials"));
        assertNull(requests.begin("setSecureCredentialsResult", "setCredentials"));
        assertSame(first, requests.finish(first.callbackName, first.id, false));

        BiometricActivityRequests.Request next = requests.begin("getSecureCredentialsResult", "getSecureCredentials");
        assertNotEquals(first.id, next.id);
    }

    @Test
    public void aDifferentResultCannotFreeOrCompleteTheActivePrompt() {
        BiometricActivityRequests requests = new BiometricActivityRequests();
        BiometricActivityRequests.Request active = requests.begin("getSecureCredentialsResult", "getSecureCredentials");

        assertNull(requests.finish("verifyResult", active.id, false));
        assertNull(requests.finish(active.callbackName, "stale", false));
        assertNull(requests.finish(active.callbackName, "stale", true));
        assertNull(requests.finish(active.callbackName, null, false));
        assertSame(active, requests.current());
        assertSame(active, requests.finish(active.callbackName, active.id, false));
        assertNull(requests.finish(active.callbackName, active.id, false));
    }

    @Test
    public void restoredRequestKeepsTheSlotAndCanFinishOnSystemCancellation() {
        BiometricActivityRequests requests = new BiometricActivityRequests();
        requests.restore("previous", "setSecureCredentialsResult", "setCredentials");
        BiometricActivityRequests.Request active = requests.current();

        assertNull(requests.begin("verifyResult", "verifyIdentity"));
        assertNull(requests.finish("verifyResult", null, true));
        assertSame(active, requests.finish(active.callbackName, null, true));
        assertNull(requests.current());
    }
}
