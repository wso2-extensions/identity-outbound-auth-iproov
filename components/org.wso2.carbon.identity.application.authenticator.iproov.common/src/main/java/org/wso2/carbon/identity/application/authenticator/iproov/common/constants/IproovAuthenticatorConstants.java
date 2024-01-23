package org.wso2.carbon.identity.application.authenticator.iproov.common.constants;

import java.util.Arrays;
import java.util.List;

/**
 * This class contains the constants used by the Iproov Authenticator.
 */
public class IproovAuthenticatorConstants {

    /**
    *
    */
    public enum ErrorMessages {

        AUTHENTICATION_FAILED_REDIRECTING_LOGIN_FAILURE("65001",
                "Authentication failed when redirecting the user to the login page."),
        USER_NOT_FOUND("65002", "User not found.",
                "User not found in the system. Please contact your system administrator."),
        RETRIEVING_REG_USER_FAILURE("65003",
                "Retrieving iProov registered user failed for the given userId."),
        RETRIEVING_VERIFY_TOKEN_FAILURE("65004",
                "Retrieving the verify token failed for the user."),
        IPROOV_BASE_URL_INVALID_FAILURE("65008", "Provided iProov base URL is invalid."),
        IPROOV_API_KEY_INVALID_FAILURE("65009", "Provided iProov api key is invalid."),
        IPROOV_API_SECRET_INVALID_FAILURE("65010", "Provided iProov api secret is invalid."),
        IPROOV_OAUTH_USERNAME_INVALID_FAILURE("65011", "Provided iProov oauth username is invalid."),
        IPROOV_OAUTH_PASSWORD_INVALID_FAILURE("65012", "Provided iProov oauth password is invalid."),

        SERVER_ERROR_INVALID_AUTHENTICATION_PROPERTIES("65013",
                "Invalid authenticator configurations or no user found."),
        SERVER_ERROR_CREATING_HTTP_CLIENT("65014", "Error while creating http client.",
                                                  "Server error encountered while creating http client."),
        IPROOV_ACCESS_TOKEN_INVALID_FAILURE("65015",
                "Provided iProov access token is either invalid or expired");
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

        ErrorMessages(String code, String message, String description) {

            this.code = code;
            this.message = message;
            this.description = description;
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

    public static class Verification {

            public static final String AUTHENTICATION = "authentication";
            public static final String ENROLLMENT = "enrollment";
    }

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
        ;
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

    public static class TokenEndpoints {

        public static final String ACCESS_TOKEN_PATH = "/access_token";
        public static final String IPROOV_VERIFY_TOKEN_PATH = "/api/v2/claim/verify/token";
        public static final String IPROOV_ENROLL_TOKEN_PATH = "/api/v2/claim/enrol/token";
        public static final String IPROOV_VALIDATE_VERIFICATION_PATH = "/api/v2/claim/verify/validate";
        public static final String IPROOV_ENROLL_VERIFICATION_PATH = "/api/v2/claim/enrol/validate";
        public static final String IPROOV_DELETE_USER_PATH = "/api/v2/users/";
    }

    public static final String SESSION_DATA_KEY = "sessionDataKey";
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
    public static final String CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials";
    public static final String IPROOV_ENROLLED_CLAIM = "http://wso2.org/claims/iproovEnrolled";
    public static final String IPROOV_LOGIN_PAGE = "/authenticationendpoint/iproovlogin.jsp";

    // REST API Parameters
    public static final String AUTH_STATUS = "authStatus";
    public static final String AUTH_REQUEST_ID = "authRequestId";
    public static final List<String> TERMINATING_STATUSES = Arrays.asList("COMPLETED", "FAILED", "CANCELED");


    /**
     * Object holding authentication mobile response status.
     */
    public enum AuthenticationStatus {

        INVALID_TOKEN("INVALID_TOKEN", "Authentication failed due to an internal server error. " +
                "To fix this, contact your system administrator."),
        INVALID_REQUEST("INVALID_REQUEST", "Invalid username provided"),
        INVALID_USER("INVALID_USER", "User does not exist in HYPR"),
        PENDING("PENDING", "Authentication with HYPR is in progress. Awaiting for the user to " +
                "authenticate via the registered smart device"),
        COMPLETED("COMPLETED", "Authentication successfully completed."),
        FAILED("FAILED", "Authentication failed. Try again."),
        CANCELED("CANCELED", "Authentication with HYPR was cancelled by the user.");

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
