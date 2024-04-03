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

package org.wso2.carbon.identity.application.authenticator.iproov.common.constants;

/**
 * This class contains the constants used by the Iproov Authenticator.
 */
public class IproovAuthenticatorConstants {

    /**
    * Error messages for iProov authenticator.
    */
    public enum ErrorMessages {

        AUTHENTICATION_FAILED_REDIRECTING_LOGIN_FAILURE("65001",
                "Authentication failed when redirecting the user to the login page."),
        USER_NOT_FOUND("65002", "User not found in the system."),
        USER_ACCOUNT_LOCKED("65003", "User account is locked Please contact your system administrator."),
        RETRIEVING_USER_STORE_FAILURE("65004", "Retrieving user store failed for the given user."),
        RETRIEVING_USER_REALM_FAILURE("65005", "Retrieving user realm failed for the given tenant."),
        RETRIEVING_REG_USER_FAILURE("65006",
                "Retrieving iProov registered user failed for the given userId."),
        RETRIEVING_VERIFY_TOKEN_FAILURE("65007",
                "Retrieving the verify token failed for the user."),
        IPROOV_BASE_URL_INVALID_FAILURE("65008", "Provided iProov base URL is invalid."),
        IPROOV_API_KEY_INVALID_FAILURE("65009", "Provided iProov api key is invalid."),
        IPROOV_API_SECRET_INVALID_FAILURE("65010", "Provided iProov api secret is invalid."),
        IPROOV_OAUTH_USERNAME_INVALID_FAILURE("65011", "Provided iProov oauth username is invalid."),
        IPROOV_OAUTH_PASSWORD_INVALID_FAILURE("65012", "Provided iProov oauth password is invalid."),
        SERVER_ERROR_INVALID_AUTHENTICATION_PROPERTIES("65013",
                "Invalid authenticator configurations or no user found."),
        IPROOV_ACCESS_TOKEN_INVALID_FAILURE("65014",
                "Provided iProov access token is either invalid or expired"),
        NO_AUTHENTICATED_USER_FOUND_FROM_PREVIOUS_STEP("65015", "No authenticated user found"),
        IPROOV_VERIFICATION_TOKEN_VALIDATING_FAILURE("65016",
                "Error while validating the iProov verification token."),
        IPROOV_REMOVING_USER_PROFILE_FAILURE("65017", "Error while removing the iProov user profile."),
        IPROOV_RETRIEVING_ACCESS_TOKEN_FAILURE("65018", "Error while retrieving the iProov access token."),
        IPROOV_SETTING_IPROOV_CLAIM_VALUE_FAILURE("65019", "Error while setting the iProov claim value."),
        IPROOV_REDIRECT_URL_BUILD_FAILURE("65020", "Error while building the iProov redirect URL."),
        ERROR_CODE_INVALID_FEDERATED_AUTHENTICATOR("65021", "No IDP found with the name IDP: " +
                                                           "%s in tenant: %s"),
        ERROR_CODE_INVALID_FEDERATED_USER_AUTHENTICATION("65023", "Can not handle federated user " +
                "authentication with TOTP as JIT Provision is not enabled for the IDP: in the tenant: %s."),
        ERROR_CODE_NO_AUTHENTICATED_USER("65024", "Can not find the authenticated user."),
        ERROR_CODE_NO_FEDERATED_USER("65025", "No federated user found."),
        ERROR_CODE_NO_USER_TENANT("65026", "Can not find the authenticated user's tenant domain.");

        private final String code;
        private final String message;
        private final String description;

        /**
         * Create an Error Message.
         *
         * @param code    Relevant error code.
         * @param message Relevant error message.
         */
        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
            description = null;
        }

        /**
         * To get the code of specific error.
         *
         * @return Error code.
         */
        public String getCode() {

            return IPROOV_API_PREFIX + code;
        }

        /**
         * To get the message of specific error.
         *
         * @return Error message.
         */
        public String getMessage() {

            return message;
        }

        /**
         * To get the description of specific error.
         *
         * @return Error description.
         */
        public String getDescription() {

            return description;
        }

        @Override
        public String toString() {

            return code + " | " + message;
        }
    }

    /**
    * Constants for iProov verification statuses.
    */
    public static class Verification {

            public static final String AUTHENTICATION = "authentication";
            public static final String ENROLLMENT = "enrollment";
            public static final String RETRY = "retry";
    }

    /**
     * Constants for iProov configuration properties.
     */
    public enum ConfigProperties {

        BASE_URL(1, "baseUrl", "Base URL",
                "Enter the base URL of your iProov server deployment."),
        OAUTH_USERNAME(2, "oauthUsername", "OAuth Username",
                "Enter the OAuth username of your iProov server deployment."),
        OAUTH_PASSWORD(3, "oauthPassword", "OAuth Password",
        "Enter the OAuth password of your iProov server deployment."),
        API_KEY(4, "apiKey", "API Key",
                "Enter the API key of your iProov server deployment."),
        API_SECRET(5, "apiSecret", "API Secret",
                "Enter the API secret of your iProov server deployment."),
        ENABLE_PROGRESSIVE_ENROLLMENT(6, "enableProgressiveEnrollment",
                "Enable Progressive Enrollment", "Enable progressive enrollment for iProov.");

        private final int displayOrder;
        private final String name;
        private final String displayName;
        private final String description;

        ConfigProperties(int displayOrder, String name, String displayName, String description) {

            this.displayOrder = displayOrder;
            this.name = name;
            this.displayName = displayName;
            this.description = description;
        }

        public int getDisplayOrder() {

            return displayOrder;
        }

        public String getName() {

            return name;
        }

        public String getDisplayName() {

            return displayName;
        }

        public String getDescription() {

            return description;
        }
    }

    /**
     * Constants for iProov payload parameters.
     */
    public static class PayloadConstants {

        public static final String API_KEY = "api_key";
        public static final String API_SECRET = "secret";
        public static final String USER_ID = "user_id";
        public static final String RESOURCE = "resource";
        public static final String ASSURANCE_TYPE = "assurance_type";
        public static final String TOKEN = "token";
        public static final String CLIENT = "client";
        public static final String RESOURCE_VALUE = "URL";
        public static final String ASSURANCE_TYPE_VALUE = "genuine_presence";
        public static final String CLIENT_VALUE = "User Agent";
    }

    /**
     * Constants for iProov token endpoints.
     */
    public static class TokenEndpoints {

        public static final String ACCESS_TOKEN_PATH = "/access_token";
        public static final String IPROOV_VERIFY_TOKEN_PATH = "/api/v2/claim/verify/token";
        public static final String IPROOV_ENROLL_TOKEN_PATH = "/api/v2/claim/enrol/token";
        public static final String IPROOV_VALIDATE_VERIFICATION_PATH = "/api/v2/claim/verify/validate";
        public static final String IPROOV_ENROLL_VERIFICATION_PATH = "/api/v2/claim/enrol/validate";
        public static final String IPROOV_DELETE_USER_PATH = "/api/v2/users/";
    }

    public static final String AUTHENTICATED_USER = "authenticatedUser";
    public static final String SESSION_DATA_KEY = "sessionDataKey";
    public static final String SCENARIO = "scenario";
    public static final String AUTHENTICATOR_NAME = "AuthenticatorName";
    public static final String AUTHENTICATOR_NAME_VALUE = "IproovAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME_VALUE = "Iproov";
    public static final String TENANT_DOMAIN = "tenantDomain";
    public static final String USERNAME = "username";
    public static final String USER_ID = "userId";
    public static final String VERIFY_TOKEN = "verifyToken";
    public static final String ENROLL_TOKEN = "enrollToken";
    public static final String IPROOV_API_PREFIX = "IPROOV-API-";
    public static final String CORRELATION_ID_KEY = "Correlation-ID";
    public static final String VERIFICATION_STATUS = "passed";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String GRANT_TYPE = "grant_type";
    public static final String CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials";
    public static final String APPLICATION_JSON_CONTENT_TYPE = "application/json";
    public static final String IPROOV_ENROLLED_CLAIM = "http://wso2.org/claims/identity/iProovEnrolled";
    public static final String IPROOV_FAILED_LOGIN_ATTEMPTS_CLAIM =
            "http://wso2.org/claims/identity/failediProovAttempts";
    public static final String USER_ID_CLAIM = "http://wso2.org/claims/userid";
    public static final String USER_ACCOUNT_LOCKED_CLAIM = "http://wso2.org/claims/identity/accountLocked";
    public static final String IPROOV_LOGIN_PAGE = "/authenticationendpoint/iproovlogin.jsp";
    public static final String IS_INITIAL_FEDERATED_USER_ATTEMPT = "isInitialFederationAttempt";

    /**
     * Object holding authentication mobile response status.
     */
    public enum AuthenticationStatus {
        PENDING("PENDING", "Authentication with iProov is in progress. Awaiting for the user to " +
                "authenticate via the registered smart device");

        private final String name;
        private final String message;

        /**
         * Create an Error Message.
         *
         * @param name    Relevant error code.
         * @param message Relevant error message.
         */
        AuthenticationStatus(String name, String message) {

            this.name = name;
            this.message = message;
        }

        public String getName() {

            return name;
        }

        public String getMessage() {

            return message;
        }
    }
}
