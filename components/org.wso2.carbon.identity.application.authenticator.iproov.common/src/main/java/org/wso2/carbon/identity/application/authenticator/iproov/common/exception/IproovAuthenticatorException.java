package org.wso2.carbon.identity.application.authenticator.iproov.common.exception;

import org.wso2.carbon.identity.base.IdentityException;

/**
 *
 */
public class IproovAuthenticatorException extends IdentityException {
    public IproovAuthenticatorException(String message) {

        super(message);
    }

    public IproovAuthenticatorException(String message, Throwable cause) {

        super(message, cause);
    }
}
