package org.wso2.carbon.identity.application.authenticator.iproov.common.exception;

/**
 * Iproov Authenticator Client Exception.
 */
public class IproovAuthenticatorClientException extends IproovAuthenticatorException {

    private final String code;

    private String description;
    public IproovAuthenticatorClientException(String message, String description, String code, Throwable cause) {

        super(message, cause);
        this.description = description;
        this.code = code;
    }
}
