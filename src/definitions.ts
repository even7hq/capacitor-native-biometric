import type { PluginListenerHandle } from '@capacitor/core';

export enum BiometryType {
  // Android, iOS
  NONE = 0,
  // iOS
  TOUCH_ID = 1,
  // iOS
  FACE_ID = 2,
  // Android
  FINGERPRINT = 3,
  // Android
  FACE_AUTHENTICATION = 4,
  // Android
  IRIS_AUTHENTICATION = 5,
  // Android
  MULTIPLE = 6,
  // Android - Device credentials (PIN, pattern, or password)
  DEVICE_CREDENTIAL = 7,
}

export enum AuthenticationStrength {
  /**
   * No authentication available, even if PIN is available but useFallback = false
   */
  NONE = 0,
  /**
   * Strong authentication: Face ID on iOS, fingerprints on devices that consider fingerprints strong (Android).
   * Note: PIN/pattern/password is NEVER considered STRONG, even when useFallback = true.
   */
  STRONG = 1,
  /**
   * Weak authentication: Face authentication on Android devices that consider face weak,
   * or PIN/pattern/password if useFallback = true (PIN is always WEAK, never STRONG).
   */
  WEAK = 2,
}

export enum AccessControl {
  /**
   * No biometric protection. Credentials are accessible without authentication.
   * This is the default behavior for backward compatibility.
   */
  NONE = 0,
  /**
   * Biometric authentication required for credential access.
   * Credentials are invalidated if biometrics change (e.g., new fingerprint enrolled).
   * More secure but credentials are lost if user modifies their biometric enrollment.
   */
  BIOMETRY_CURRENT_SET = 1,
  /**
   * Biometric authentication required for credential access.
   * Credentials survive new biometric enrollment (e.g., adding a new fingerprint).
   * More lenient — recommended for most apps.
   */
  BIOMETRY_ANY = 2,
}

export interface Credentials {
  username: string;
  password: string;
}

export interface IsAvailableOptions {
  /**
   * Counts the device passcode toward availability when a secure lock screen is configured.
   * Before Android 11, this check can count the passcode even though the verification prompt cannot offer it.
   * To offer the passcode in the Android verification dialog, set the `useFallback` option
   * of BiometricOptions when calling `verifyIdentity()` on Android 11 or newer.
   */
  useFallback: boolean;
}

/**
 * Result from isAvailable() method indicating biometric authentication availability.
 */
export interface AvailableResult {
  /**
   * Whether authentication is available (biometric or fallback if useFallback is true)
   */
  isAvailable: boolean;
  /**
   * The strength of available authentication method (STRONG, WEAK, or NONE)
   */
  authenticationStrength: AuthenticationStrength;
  /**
   * The primary biometry type available on the device.
   * On Android devices with multiple biometry types, this returns MULTIPLE.
   * Use this for display purposes only - always use isAvailable for logic decisions.
   */
  biometryType: BiometryType;
  /**
   * Whether the device has a secure lock screen (PIN, pattern, or password).
   * This is independent of biometric enrollment.
   */
  deviceIsSecure: boolean;
  /**
   * Whether strong biometry (Face ID, Touch ID, or fingerprint on devices that consider it strong)
   * is specifically available, separate from weak biometry or device credentials.
   */
  strongBiometryIsAvailable: boolean;
  /**
   * Error code from BiometricAuthError enum. Only present when isAvailable is false.
   * Indicates why biometric authentication is not available.
   * @see BiometricAuthError
   */
  errorCode?: BiometricAuthError;
}

export interface BiometricOptions {
  reason?: string;
  title?: string;
  subtitle?: string;
  description?: string;
  negativeButtonText?: string;
  /**
   * Requests the device passcode as an alternative in the verification dialog.
   * On Android 11 or newer, the dialog can offer a configured PIN, pattern or password
   * alongside strong biometrics. This option defaults to false on Android. On older
   * Android versions, the default dialog keeps strong biometrics and the cancel button.
   */
  useFallback?: boolean;
  /**
   * Only for iOS.
   * Set the text for the fallback button in the authentication dialog.
   * If this property is not specified, the default text is set by the system.
   */
  fallbackTitle?: string;
  /**
   * Only for Android.
   * Set a maximum number of attempts for biometric authentication. The maximum allowed by android is 5.
   * @default 1
   */
  maxAttempts?: number;
  /**
   * Only for Android.
   * Specify which biometry types are allowed for authentication.
   * If not specified, the Android dialog defaults to strong biometrics. The
   * `useFallback` option can also add the device credential on Android 11 or newer.
   * @example [BiometryType.FINGERPRINT, BiometryType.FACE_AUTHENTICATION]
   */
  allowedBiometryTypes?: BiometryType[];
}

export interface GetCredentialOptions {
  server: string;
}

export interface SetCredentialOptions {
  username: string;
  password: string;
  server: string;
  /**
   * Access control level for the stored credentials.
   * When set to BIOMETRY_CURRENT_SET or BIOMETRY_ANY, the credentials are
   * hardware-protected and require biometric authentication to access.
   *
   * On iOS, this adds SecAccessControl to the Keychain item.
   * On Android, this creates a biometric-protected Keystore key and requires
   * BiometricPrompt authentication for both storing and retrieving credentials.
   *
   * @default AccessControl.NONE
   * @since 8.4.0
   */
  accessControl?: AccessControl;
  /**
   * Title for the biometric prompt when storing credentials (accessControl > 0).
   * Android only; iOS uses the system prompt.
   */
  title?: string;
  /**
   * Negative button label for the biometric prompt when storing credentials.
   * Android only.
   */
  negativeButtonText?: string;
}

export interface GetSecureCredentialsOptions {
  server: string;
  /**
   * Reason for requesting biometric authentication.
   * Displayed in the biometric prompt on both iOS and Android.
   */
  reason?: string;
  /**
   * Title for the biometric prompt.
   * Only for Android.
   */
  title?: string;
  /**
   * Subtitle for the biometric prompt.
   * Only for Android.
   */
  subtitle?: string;
  /**
   * Description for the biometric prompt.
   * Only for Android.
   */
  description?: string;
  /**
   * Text for the negative/cancel button.
   * Only for Android.
   */
  negativeButtonText?: string;
}

export interface DeleteCredentialOptions {
  server: string;
}

export interface IsCredentialsSavedOptions {
  server: string;
}

export interface IsCredentialsSavedResult {
  isSaved: boolean;
}

/**
 * Biometric authentication error codes.
 * The `isAvailable()` result reports these codes as numbers in `errorCode`.
 * Native authentication errors expose the numeric value as a string in the rejection's `code`.
 *
 * Keep this in sync with BiometricAuthError in README.md
 * Update whenever `convertToPluginErrorCode` functions are modified
 */
export enum BiometricAuthError {
  /**
   * Unknown error occurred. On Android, this code is also returned when another biometric prompt is already open.
   */
  UNKNOWN_ERROR = 0,
  /**
   * Biometrics are unavailable (no hardware or hardware error)
   * Platform: Android, iOS
   */
  BIOMETRICS_UNAVAILABLE = 1,
  /**
   * User has been locked out due to too many failed attempts
   * Platform: Android, iOS
   */
  USER_LOCKOUT = 2,
  /**
   * No biometrics are enrolled on the device
   * Platform: Android, iOS
   */
  BIOMETRICS_NOT_ENROLLED = 3,
  /**
   * User is temporarily locked out (Android: 30 second lockout)
   * Platform: Android
   */
  USER_TEMPORARY_LOCKOUT = 4,
  /**
   * Authentication failed (user did not authenticate successfully)
   * Platform: Android, iOS
   */
  AUTHENTICATION_FAILED = 10,
  /**
   * App canceled the authentication (iOS only)
   * Platform: iOS
   */
  APP_CANCEL = 11,
  /**
   * Invalid context (iOS only)
   * Platform: iOS
   */
  INVALID_CONTEXT = 12,
  /**
   * Authentication was not interactive (iOS only)
   * Platform: iOS
   */
  NOT_INTERACTIVE = 13,
  /**
   * Passcode/PIN is not set on the device
   * Platform: Android, iOS
   */
  PASSCODE_NOT_SET = 14,
  /**
   * System canceled the authentication (e.g., due to screen lock)
   * Platform: Android, iOS
   */
  SYSTEM_CANCEL = 15,
  /**
   * User canceled the authentication
   * Platform: Android, iOS
   */
  USER_CANCEL = 16,
  /**
   * User chose to use fallback authentication method
   * Platform: Android, iOS
   */
  USER_FALLBACK = 17,
  /**
   * No usable biometric-protected credentials exist for the requested server.
   * `getSecureCredentials()` reports this error as `code: "21"` when the user needs to enroll again.
   */
  NO_PROTECTED_CREDENTIALS_FOUND = 21,
}

/**
 * Callback type for biometry change listener
 */
export type BiometryChangeListener = (result: AvailableResult) => void;

export interface NativeBiometricPlugin {
  /**
   * Checks if biometric authentication hardware is available.
   * @param {IsAvailableOptions} [options]
   * @returns {Promise<AvailableResult>}
   * @memberof NativeBiometricPlugin
   * @since 1.0.0
   */
  isAvailable(options?: IsAvailableOptions): Promise<AvailableResult>;

  /**
   * Adds a listener that is called when the app resumes from background.
   * This is useful to detect if biometry availability has changed while
   * the app was in the background (e.g., user enrolled/unenrolled biometrics).
   *
   * @param eventName - Must be 'biometryChange'
   * @param {BiometryChangeListener} listener - Callback function that receives the updated AvailableResult
   * @returns {Promise<PluginListenerHandle>} Handle to remove the listener
   * @since 7.6.0
   *
   * @example
   * ```typescript
   * const handle = await NativeBiometric.addListener('biometryChange', (result) => {
   *   console.log('Biometry availability changed:', result.isAvailable);
   * });
   *
   * // To remove the listener:
   * await handle.remove();
   * ```
   */
  addListener(eventName: 'biometryChange', listener: BiometryChangeListener): Promise<PluginListenerHandle>;
  /**
   * Prompts the user to authenticate with biometrics.
   * @param {BiometricOptions} [options]
   * @returns {Promise<any>}
   * @memberof NativeBiometricPlugin
   * @since 1.0.0
   */
  verifyIdentity(options?: BiometricOptions): Promise<void>;
  /**
   * Gets the stored credentials for a given server.
   * @param {GetCredentialOptions} options
   * @returns {Promise<Credentials>}
   * @memberof NativeBiometricPlugin
   * @since 1.0.0
   */
  getCredentials(options: GetCredentialOptions): Promise<Credentials>;
  /**
   * Stores the given credentials for a given server.
   * @param {SetCredentialOptions} options
   * @returns {Promise<any>}
   * @memberof NativeBiometricPlugin
   * @since 1.0.0
   */
  setCredentials(options: SetCredentialOptions): Promise<void>;
  /**
   * Deletes the stored credentials for a given server.
   * @param {DeleteCredentialOptions} options
   * @returns {Promise<any>}
   * @memberof NativeBiometricPlugin
   * @since 1.0.0
   */
  deleteCredentials(options: DeleteCredentialOptions): Promise<void>;
  /**
   * Gets the stored credentials for a given server, requiring biometric authentication.
   * Credentials must have been stored with accessControl set to BIOMETRY_CURRENT_SET or BIOMETRY_ANY.
   *
   * On iOS, the system automatically shows the biometric prompt when accessing the protected Keychain item.
   * On Android, BiometricPrompt is shown with a CryptoObject bound to the credential decryption key.
   * Credentials stored with a legacy Android authentication window use a strong biometric prompt
   * followed immediately by decryption with the original key.
   * Native rejections with a BiometricAuthError use a string in `code`, such as `"21"` for missing credentials.
   *
   * @param {GetSecureCredentialsOptions} options
   * @returns {Promise<Credentials>}
   * @memberof NativeBiometricPlugin
   * @since 8.4.0
   */
  getSecureCredentials(options: GetSecureCredentialsOptions): Promise<Credentials>;
  /**
   * Checks if credentials are already saved for a given server.
   * @param {IsCredentialsSavedOptions} options
   * @returns {Promise<IsCredentialsSavedResult>}
   * @memberof NativeBiometricPlugin
   * @since 7.3.0
   */
  isCredentialsSaved(options: IsCredentialsSavedOptions): Promise<IsCredentialsSavedResult>;

  /**
   * Get the native Capacitor plugin version.
   *
   * @returns Promise that resolves with the plugin version
   * @since 1.0.0
   */
  getPluginVersion(): Promise<{ version: string }>;
}
