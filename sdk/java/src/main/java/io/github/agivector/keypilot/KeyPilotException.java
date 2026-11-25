/*
 * Description: Defines stable exceptions returned by the KeyPilot Java SDK.
 * Author: vectorshi
 * Created: 2026-11-25
 */
package io.github.agivector.keypilot;

/**
 * Description: Represents a configuration, refresh, key, or verification failure.
 * Author: vectorshi
 * Created: 2026-11-25
 * Parameters: None.
 * Returns: None.
 */
public final class KeyPilotException extends RuntimeException {
    private final SdkErrorCode code;

    /**
     * Description: Creates an SDK exception without a lower-level cause.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   code: Stable SDK error code.
     *   message: Diagnostic message without sensitive key material.
     * Returns: None.
     */
    public KeyPilotException(SdkErrorCode code, String message) {
        super("keypilot sdk error code=" + code.getCode() + ": " + message);
        this.code = code;
    }

    /**
     * Description: Creates an SDK exception with a lower-level cause.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   code: Stable SDK error code.
     *   message: Diagnostic message without sensitive key material.
     *   cause: Lower-level exception.
     * Returns: None.
     */
    public KeyPilotException(SdkErrorCode code, String message, Throwable cause) {
        super("keypilot sdk error code=" + code.getCode() + ": " + message, cause);
        this.code = code;
    }

    /**
     * Description: Returns the stable SDK error code.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns:
     *   SdkErrorCode: Stable error category.
     */
    public SdkErrorCode getCode() {
        return code;
    }
}
