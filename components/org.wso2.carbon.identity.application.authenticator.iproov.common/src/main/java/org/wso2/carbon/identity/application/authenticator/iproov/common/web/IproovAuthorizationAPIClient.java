package org.wso2.carbon.identity.application.authenticator.iproov.common.web;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authenticator.iproov.common.constants.IproovAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.iproov.common.exception.IproovAuthenticatorClientException;
import org.wso2.carbon.identity.application.authenticator.iproov.common.exception.IproovAuthenticatorServerException;
import org.wso2.carbon.identity.application.authenticator.iproov.common.exception.IproovAuthnFailedException;

import java.io.IOException;
import java.net.URISyntaxException;

/**
 * This class contains all the functions related to handling the API calls to the iProov server.
 */
public class IproovAuthorizationAPIClient {

    private static final Log LOG = LogFactory.getLog(IproovAuthorizationAPIClient.class);

    /**
     *  This method is used to get the token from the iProov server.
     *
     *  @param baseUrl The base URL of the iProov server.
     *  @param tokenPath The token path of the iProov server.
     *  @param apiKey The API key of the created iProov service provider.
     *  @param secret The secret of the created iProov service provider.
     *  @param userId The user ID.
     *  @return The token from the iProov server.
     *  @throws IproovAuthnFailedException If an error occurred when getting the token from the iProov server.
     */
    public static String getToken(String baseUrl, String tokenPath, String apiKey, String secret, String userId)
            throws IproovAuthnFailedException {

        try {
            URIBuilder uriBuilder = new URIBuilder(baseUrl);
            uriBuilder.setPath(tokenPath);

            String payload =  createTokenPayload(apiKey, secret, userId);
            HttpResponse response = IproovWebUtils.httpPost(uriBuilder.build(), payload, apiKey, secret);

            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);
                JSONObject jsonObject = new JSONObject(jsonString);
                return jsonObject.getString(IproovAuthenticatorConstants.PayloadConstants.TOKEN);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
                throw getIproovAuthnFailedException(
                        IproovAuthenticatorConstants.ErrorMessages.SERVER_ERROR_INVALID_AUTHENTICATION_PROPERTIES);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                throw getIproovAuthnFailedException(
                        IproovAuthenticatorConstants.ErrorMessages.IPROOV_ACCESS_TOKEN_INVALID_FAILURE);
            } else {
                throw getIproovAuthnFailedException(
                        IproovAuthenticatorConstants.ErrorMessages.RETRIEVING_VERIFY_TOKEN_FAILURE);
            }
        } catch (URISyntaxException e) {
            throw getIproovAuthnFailedException(
                    IproovAuthenticatorConstants.ErrorMessages.IPROOV_BASE_URL_INVALID_FAILURE, e);
        } catch (IOException | IproovAuthenticatorServerException | IproovAuthenticatorClientException e) {
            throw getIproovAuthnFailedException(
                    IproovAuthenticatorConstants.ErrorMessages.RETRIEVING_VERIFY_TOKEN_FAILURE, e);
        }
    }

    /**
     * This method is used to validate the verification token from the iProov server.
     *
     * @param baseUrl The base URL of the iProov server.
     * @param tokenPath The token path of the iProov server.
     * @param apiKey The API key of the created iProov service provider.
     * @param secret The secret of the created iProov service provider.
     * @param userId The user ID.
     * @param token The token from the iProov server.
     * @return The status of the verification token.
     * @throws IproovAuthnFailedException If an error occurred when validating the verification token from the iProov
     * server.
     */
    public static boolean validateVerification(String baseUrl, String tokenPath, String apiKey, String secret,
                                              String userId, String token) throws IproovAuthnFailedException {

        try {
            URIBuilder uriBuilder = new URIBuilder(baseUrl);
            uriBuilder.setPath(tokenPath);

            HttpResponse response = IproovWebUtils.httpPost(uriBuilder.build(),
                    createVerificationPayload(apiKey, secret, userId, token), apiKey, secret);

            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {

                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);

                JSONObject jsonObject = new JSONObject(jsonString);
                return Boolean.parseBoolean(jsonObject.get(IproovAuthenticatorConstants.VERIFICATION_STATUS).toString());
            }
            return false;
        } catch (URISyntaxException | IOException | IproovAuthenticatorClientException |
                 IproovAuthenticatorServerException e) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages
                    .IPROOV_VERIFICATION_TOKEN_VALIDATING_FAILURE, e);
        }
    }

    /**
     * This method is used to create the token payload.
     *
     * @param apiKey The API key of the created iProov service provider.
     * @param secret The secret of the created iProov service provider.
     * @param userId The user ID.
     * @return The token payload.
     */
    private static String createTokenPayload(String apiKey, String secret, String userId) {

        JSONObject payload = new JSONObject();

        payload.put(IproovAuthenticatorConstants.PayloadConstants.API_KEY, apiKey);
        payload.put(IproovAuthenticatorConstants.PayloadConstants.API_SECRET, secret);
        payload.put(IproovAuthenticatorConstants.PayloadConstants.RESOURCE,
                IproovAuthenticatorConstants.PayloadConstants.RESOURCE_VALUE);
        payload.put(IproovAuthenticatorConstants.PayloadConstants.ASSURANCE_TYPE,
                IproovAuthenticatorConstants.PayloadConstants.ASSURANCE_TYPE_VALUE);
        payload.put(IproovAuthenticatorConstants.PayloadConstants.USER_ID, userId);

        return payload.toString();
    }

    /**
     * This method is used to create the verification payload.
     *
     * @param apiKey The API key of the created iProov service provider.
     * @param secret The secret of the created iProov service provider.
     * @param userId The user ID.
     * @param token The token from the iProov server.
     * @return The verification payload.
     */
    private static String createVerificationPayload(String apiKey, String secret, String userId, String token) {

        JSONObject payload = new JSONObject();

        payload.put(IproovAuthenticatorConstants.PayloadConstants.API_KEY, apiKey);
        payload.put(IproovAuthenticatorConstants.PayloadConstants.API_SECRET, secret);
        payload.put(IproovAuthenticatorConstants.PayloadConstants.USER_ID, userId);
        payload.put(IproovAuthenticatorConstants.PayloadConstants.TOKEN, token);
        payload.put(IproovAuthenticatorConstants.PayloadConstants.CLIENT, IproovAuthenticatorConstants
                .PayloadConstants.CLIENT_VALUE);

        return payload.toString();
    }

    /**
     * This method is used to remove the iProov user profile from the iProov server.
     *
     * @param baseUrl The base URL of the iProov server.
     * @param apiKey The API key of the created iProov service provider.
     * @param clientId The client ID of the created iProov service provider.
     * @param secret The secret of the created iProov service provider.
     * @param userId The user ID.
     * @throws IproovAuthnFailedException If an error occurred when removing the iProov user profile from the iProov
     * server.
     */
    public static void removeIproovUserProfile(String baseUrl, String apiKey, String clientId, String secret,
                                               String userId) throws IproovAuthnFailedException {

        try {
            URIBuilder uriBuilder = new URIBuilder(baseUrl);
            uriBuilder.setPath(IproovAuthenticatorConstants.TokenEndpoints.IPROOV_DELETE_USER_PATH + "/" + userId);
            HttpResponse response = IproovWebUtils.httpDelete(uriBuilder.build(), baseUrl, apiKey, clientId, secret);

            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);
                JSONObject jsonObject = new JSONObject(jsonString);
                if (jsonObject.get("status").equals("Deleted")) {
                    LOG.info("Successfully deleted the user profile from iProov server.");
                }
            }
        } catch (URISyntaxException | IOException | IproovAuthenticatorClientException |
                 IproovAuthenticatorServerException e) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages
                    .IPROOV_REMOVING_USER_PROFILE_FAILURE, e);
        }
    }
    
    private static IproovAuthnFailedException getIproovAuthnFailedException(
            IproovAuthenticatorConstants.ErrorMessages errorMessage) {

        return new IproovAuthnFailedException(errorMessage.getCode(), errorMessage.getMessage());
    }

    private static IproovAuthnFailedException getIproovAuthnFailedException(
            IproovAuthenticatorConstants.ErrorMessages errorMessage, Exception e) {

        return new IproovAuthnFailedException(errorMessage.getCode(), errorMessage.getMessage(), e);
    }
}
