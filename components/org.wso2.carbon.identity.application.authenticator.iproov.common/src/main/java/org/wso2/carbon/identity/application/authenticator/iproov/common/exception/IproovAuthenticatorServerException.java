package org.wso2.carbon.identity.application.authenticator.iproov.common.exception;

import org.wso2.carbon.identity.base.IdentityException;

/**
 *
 */
public class IproovAuthenticatorServerException extends IproovAuthenticatorException {

    public IproovAuthenticatorServerException(String message) {

        super(message);
    }

    public IproovAuthenticatorServerException(String message, Throwable cause) {

        super(message, cause);
    }
}
