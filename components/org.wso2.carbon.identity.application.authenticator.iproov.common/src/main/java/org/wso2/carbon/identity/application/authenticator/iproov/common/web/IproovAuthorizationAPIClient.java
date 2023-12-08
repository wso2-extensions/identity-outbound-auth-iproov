package org.wso2.carbon.identity.application.authenticator.iproov.common.web;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authenticator.iproov.common.constants.IproovAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.iproov.common.exception.IproovAuthnFailedException;
import org.wso2.carbon.identity.application.authenticator.iproov.common.exception.IproovClientException;
import org.wso2.carbon.identity.application.authenticator.iproov.common.model.IproovRegisteredUser;

import java.io.IOException;
import java.lang.reflect.Type;
import java.net.URISyntaxException;

/**
 * This class contains all the functions related to handling the API calls to the iProov server.
 */
public class IproovAuthorizationAPIClient {

    public static IproovRegisteredUser getIproovRegisteredUser(String baseUrl, String tokenEndpoint, String clientId,
                                                               String clientSecret, String username)
            throws IproovAuthnFailedException {

        try {
            // Get user API: {{baseUrl}}/users/{{username}}
            URIBuilder uriBuilder = new URIBuilder(baseUrl);
            uriBuilder.setPath(IproovAuthenticatorConstants.IPROOV_GET_USER_PATH + username);

            HttpResponse response = IproovWebUtils.httpGet(uriBuilder.build(), tokenEndpoint, clientId, clientSecret);

            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {

                Gson gson = new GsonBuilder().create();
                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);

                Type type = new TypeToken<IproovRegisteredUser>() {
                }.getType();

                return new IproovRegisteredUser(gson.fromJson(jsonString, type));
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
                throw getIproovAuthnFailedException(
                        IproovAuthenticatorConstants.ErrorMessages.SERVER_ERROR_INVALID_AUTHENTICATION_PROPERTIES);
            } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                throw getIproovAuthnFailedException(
                        IproovAuthenticatorConstants.ErrorMessages.IPROOV_ACCESS_TOKEN_INVALID_FAILURE);
            } else {
                throw getIproovAuthnFailedException(
                        IproovAuthenticatorConstants.ErrorMessages.RETRIEVING_REG_USER_FAILURE);
            }
        } catch (URISyntaxException e) {
            throw getIproovAuthnFailedException(
                    IproovAuthenticatorConstants.ErrorMessages.IPROOV_BASE_URL_INVALID_FAILURE, e);
        } catch (IproovClientException e) {
            throw getIproovAuthnFailedException(
                    IproovAuthenticatorConstants.ErrorMessages.SERVER_ERROR_CREATING_HTTP_CLIENT, e);
        } catch (IOException e) {
            throw getIproovAuthnFailedException(
                    IproovAuthenticatorConstants.ErrorMessages.RETRIEVING_REG_USER_FAILURE, e);
        }
    }

    public static String getVerifyToken(String baseUrl, String apiKey, String secret, String userId, String clientId,
                                        String clientSecret) throws IproovAuthnFailedException {

        try {
            // Get verify token: {{baseUrl}}/claim/verify/token
            URIBuilder uriBuilder = new URIBuilder(baseUrl);
            uriBuilder.setPath(IproovAuthenticatorConstants.IPROOV_VERIFY_TOKEN_PATH);

            HttpResponse response = IproovWebUtils.httpPost(uriBuilder.build(),
                    createTokenPayload(apiKey, secret, userId), clientId, clientSecret);

            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {

                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);

                JSONObject jsonObject = new JSONObject(jsonString);
                return jsonObject.getString(IproovAuthenticatorConstants.TOKEN);
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
        } catch (IproovClientException e) {
            throw getIproovAuthnFailedException(
                    IproovAuthenticatorConstants.ErrorMessages.SERVER_ERROR_CREATING_HTTP_CLIENT, e);
        } catch (IOException e) {
            throw getIproovAuthnFailedException(
                    IproovAuthenticatorConstants.ErrorMessages.RETRIEVING_VERIFY_TOKEN_FAILURE, e);
        }
    }

    public static boolean validateVerification(String baseUrl, String apiKey, String secret, String userId,
                                              String token, String clientId, String clientSecret) {

        try {
            // Validate verification: {{baseUrl}}/claim/verify/validate
            URIBuilder uriBuilder = new URIBuilder(baseUrl);
            uriBuilder.setPath(IproovAuthenticatorConstants.IPROOV_VALIDATE_VERIFICATION_PATH);

            HttpResponse response = IproovWebUtils.httpPost(uriBuilder.build(),
                    createVerificationPayload(apiKey, secret, userId, token), clientId, clientSecret);

            if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {

                HttpEntity entity = response.getEntity();
                String jsonString = EntityUtils.toString(entity);

                JSONObject jsonObject = new JSONObject(jsonString);
                return Boolean.parseBoolean(jsonObject.getString(IproovAuthenticatorConstants.VERIFICATION_STATUS));
            }
        } catch (URISyntaxException | IOException | IproovClientException e) {
            throw new RuntimeException(e);
        }
        return false;
    }

    private static String createTokenPayload(String apiKey, String secret, String userId) {

        JSONObject payload = new JSONObject();

        payload.put(IproovAuthenticatorConstants.API_KEY, apiKey);
        payload.put(IproovAuthenticatorConstants.SECRET, secret);
        payload.put(IproovAuthenticatorConstants.RESOURCE, IproovAuthenticatorConstants.RESOURCE_VALUE);
        payload.put(IproovAuthenticatorConstants.ASSURANCE_TYPE, IproovAuthenticatorConstants.ASSURANCE_TYPE_VALUE);
        payload.put(IproovAuthenticatorConstants.USER_ID, userId);

        return payload.toString();
    }

    private static String createVerificationPayload(String apiKey, String secret, String userId, String token) {

        JSONObject payload = new JSONObject();

        payload.put(IproovAuthenticatorConstants.API_KEY, apiKey);
        payload.put(IproovAuthenticatorConstants.SECRET, secret);
        payload.put(IproovAuthenticatorConstants.USER_ID, userId);
        payload.put(IproovAuthenticatorConstants.TOKEN, token);
        payload.put(IproovAuthenticatorConstants.CLIENT, IproovAuthenticatorConstants.CLIENT_VALUE);
        payload.put(IproovAuthenticatorConstants.RISK_PROFILE, IproovAuthenticatorConstants.RISK_PROFILE_VALUE);

        return payload.toString();
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
