/*
 * Description: Defines stable numeric error codes exposed by the Java SDK.
 * Author: vectorshi
 * Created: 2026-11-25
 */
package io.github.codepunkgm.keypilot;

/**
 * Description: Identifies a stable SDK failure category.
 * Author: vectorshi
 * Created: 2026-11-25
 * Parameters: None.
 * Returns: None.
 */
public enum SdkErrorCode {
    INVALID_ARGUMENT(6001),
    ALGORITHM_NOT_ALLOWED(6002),
    KEY_NOT_FOUND(6003),
    KEY_INVALID(6004),
    SIGNATURE_INVALID(6005),
    JWKS_UNAVAILABLE(6006),
    JWKS_INVALID_RESPONSE(6007),
    CACHE_EXPIRED(6008),
    CONFIGURATION_ERROR(6009),
    INTERNAL_ERROR(6999);

    private final int code;

    /**
     * Description: Creates one stable numeric SDK error value.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters:
     *   code: Stable numeric SDK error code.
     * Returns: None.
     */
    SdkErrorCode(int code) {
        this.code = code;
    }

    /**
     * Description: Returns the stable numeric SDK error code.
     * Author: vectorshi
     * Created: 2026-11-25
     * Parameters: None.
     * Returns:
     *   int: Stable numeric SDK error code.
     */
    public int getCode() {
        return code;
    }
}
