package org.wso2.carbon.identity.application.authenticator.iproov.common.exception;

/**
 * An exception class which is used to send a iProov specific error code and error message when the iProov connector
 * encountered any errors with regard to HTTP Client connections.
 */
public class IproovAuthenticatorClientException extends IproovAuthenticatorException {

    private final String code;

    private String description;

    /**
     * An overloaded constructor which is used to throw an error code and error message once the HYPR connector
     * unable to proceed the authentication with HYPR due to HTTP client connection issue.
     *
     * @param code    An error code specified to the authenticator.
     * @param message An error message specified to the authenticator.
     */
    public IproovAuthenticatorClientException(String message, String code) {

        super(message);
        this.code = code;
    }

    /**
     * An overloaded constructor which is used to throw an error code, error message and error description once the
     * HYPR connector unable to proceed the authentication with HYPR due to HTTP client connection issue.
     *
     * @param code        An error code specified to the authenticator.
     * @param message     An error message specified to the authenticator.
     * @param description An in-detail error description specified to the authenticator.
     */
    public IproovAuthenticatorClientException(String message, String description, String code) {

        super(message);
        this.description = description;
        this.code = code;
    }

    /**
     * An overloaded constructor which is used to throw an error code, error message, error description and
     * throwable cause once the HYPR connector unable to proceed the authentication with HYPR due to
     * HTTP client connection issue.
     *
     * @param code        An error code specified to the authenticator.
     * @param message     An error message specified to the authenticator.
     * @param description An in-detail error description specified to the authenticator.
     * @param cause       Thrown exception.
     */
    public IproovAuthenticatorClientException(String message, String description, String code, Throwable cause) {

        super(message, cause);
        this.description = description;
        this.code = code;
    }
}
