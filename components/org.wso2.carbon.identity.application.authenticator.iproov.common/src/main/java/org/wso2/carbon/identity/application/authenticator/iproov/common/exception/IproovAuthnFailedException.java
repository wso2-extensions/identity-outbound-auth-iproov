/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

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
