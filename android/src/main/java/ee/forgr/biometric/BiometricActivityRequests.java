package ee.forgr.biometric;

import java.util.UUID;

/** Keeps the original request associated with the single outstanding biometric activity. */
final class BiometricActivityRequests {

    static final String EXTRA_REQUEST_ID = "ee.forgr.biometric.requestId";

    static final class Request {

        final String id;
        final String callbackName;
        final String methodName;

        Request(String id, String callbackName, String methodName) {
            this.id = id;
            this.callbackName = callbackName;
            this.methodName = methodName;
        }
    }

    // Accessed on the main thread, together with the Activity Result launcher and its callbacks.
    private Request pending;

    Request begin(String callbackName, String methodName) {
        if (pending != null) {
            return null;
        }
        pending = new Request(UUID.randomUUID().toString(), callbackName, methodName);
        return pending;
    }

    Request current() {
        return pending;
    }

    void restore(String id, String callbackName, String methodName) {
        pending = new Request(id, callbackName, methodName);
    }

    Request finish(String callbackName, String id, boolean cancelled) {
        Request request = pending;
        if (request == null || !request.callbackName.equals(callbackName) || !(request.id.equals(id) || (id == null && cancelled))) {
            return null;
        }
        pending = null;
        return request;
    }
}
