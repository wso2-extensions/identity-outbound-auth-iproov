package org.wso2.carbon.identity.application.authenticator.iproov.common.exception;

import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;

/**
 * An exception class which is used to send an iProov specific error code and error message when authenticator unable
 * to proceed the authentication.
 */
public class IproovAuthnFailedException extends AuthenticationFailedException {

    /**
     * An overloaded constructor which is used to throw an error code,error message and throwable cause once
     * authenticator unable to proceed the authentication with iProov.
     *
     * @param code    An error code specified to the authenticator.
     * @param message An error message specified to the authenticator.
     * @param cause   Thrown exception.
     */
    public IproovAuthnFailedException(String code, String message, Throwable cause) {

        super(code, message, cause);
    }

    /**
     * An overloaded constructor which is used to throw an error code and error message once
     * authenticator unable to proceed the authentication with iProov.
     *
     * @param code    An error code specified to the authenticator.
     * @param message An error message specified to the authenticator.
     */
    public IproovAuthnFailedException(String code, String message) {

        super(code, message);
    }
}
