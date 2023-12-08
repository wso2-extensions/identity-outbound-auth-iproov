package org.wso2.carbon.identity.application.authenticator.iproov.common.constants;

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

        RETRIEVING_REG_USER_FAILURE("65003",
                "Retrieving iProov registered user failed for the given userId."),
        RETRIEVING_VERIFY_TOKEN_FAILURE("65004",
                "Retrieving the verify token failed for the user."),
        IPROOV_BASE_URL_INVALID_FAILURE("65008", "Provided iProov base URL is invalid."),
        IPROOV_ACCESS_TOKEN_INVALID_FAILURE("65010",
                "Provided iProov access token is either invalid or expired"),
        SERVER_ERROR_INVALID_AUTHENTICATION_PROPERTIES("65013",
                "Invalid authenticator configurations or no user found."),
        SERVER_ERROR_CREATING_HTTP_CLIENT("65014", "Error while creating http client.",
                                                  "Server error encountered while creating http client.")
        ;
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

    public static final String IPROOV_API_PREFIX = "IPROOV-API-";
    public static final String API_KEY = "api_key";
    public static final String SECRET = "secret";
    public static final String USER_ID = "user_id";
    public static final String RESOURCE = "resource";
    public static final String ASSURANCE_TYPE = "assurance_type";
    public static final String TOKEN = "token";
    public static final String CLIENT = "client";
    public static final String RISK_PROFILE = "risk_profile";
    public static final String VERIFICATION_STATUS = "passed";

    public static final String RESOURCE_VALUE = "URL";
    public static final String ASSURANCE_TYPE_VALUE = "genuine_presence";
    public static final String CLIENT_VALUE = "User Agent";
    public static final String RISK_PROFILE_VALUE = "low";

    public static final String CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials";
    public static final String IPROOV_GET_USER_PATH = "/users/";
    public static final String IPROOV_VERIFY_TOKEN_PATH = "/claim/verify/token";
    public static final String IPROOV_VALIDATE_VERIFICATION_PATH = "/claim/verify/validate";
}
