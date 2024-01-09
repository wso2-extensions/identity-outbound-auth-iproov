package org.wso2.carbon.identity.application.authenticator.iproov.common.web;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.BufferedHttpEntity;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.message.BasicNameValuePair;
import org.wso2.carbon.identity.application.authenticator.iproov.common.constants.IproovAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.iproov.common.exception.IproovClientException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.wso2.carbon.identity.application.authenticator.iproov.common.constants.IproovAuthenticatorConstants.CLIENT_CREDENTIALS_GRANT_TYPE;

/**
 *
 */
public class IproovWebUtils {

    private static final Log LOG = LogFactory.getLog(IproovWebUtils.class);
    private IproovWebUtils() {

    }

    public static HttpResponse httpGet(URI requestURL, String baseUrl, String apiKey, String clientId,
                                       String clientSecret) throws IOException, IproovClientException {

        HttpGet request = new HttpGet(requestURL);
        String accessToken = getAccessToken(baseUrl, apiKey, clientId, clientSecret);
        LOG.info("Access Token: " + accessToken);

        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);

        CloseableHttpClient client = HttpClientManager.getInstance().getHttpClient();
        try (CloseableHttpResponse response = client.execute(request)) {
            return toHttpResponse(response);
        }
    }

    public static HttpResponse httpPost(URI requestURL, String payload, String clientId, String clientSecret)
            throws IOException, IproovClientException {

        HttpPost request = new HttpPost(requestURL);
        buildBasicAuthHeader(request, clientId, clientSecret);
        request.addHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        request.setEntity(new StringEntity(payload, StandardCharsets.UTF_8));

        CloseableHttpClient client = HttpClientManager.getInstance().getHttpClient();
        try (CloseableHttpResponse response = client.execute(request)) {
            return toHttpResponse(response);
        }
    }

    private static HttpResponse toHttpResponse(final CloseableHttpResponse response) throws IOException {

        final HttpResponse result = new BasicHttpResponse(response.getStatusLine());
        if (response.getEntity() != null) {
            result.setEntity(new BufferedHttpEntity(response.getEntity()));
        }
        return result;
    }

    private static String getAccessToken(String baseUrl, String apiKey, String clientId, String clientSecret) {

        try (CloseableHttpClient httpClient = HttpClientBuilder.create().useSystemProperties().build()) {

            String tokenEndpoint = baseUrl + "/" + apiKey +
                    IproovAuthenticatorConstants.TokenEndpoints.ACCESS_TOKEN_PATH;
            HttpPost httpPost = new HttpPost(tokenEndpoint);
            buildBasicAuthHeader(httpPost, clientId, clientSecret);
            List<BasicNameValuePair> urlParameters = new ArrayList<>();
            urlParameters.add(new BasicNameValuePair("grant_type", CLIENT_CREDENTIALS_GRANT_TYPE));
            httpPost.setEntity(new UrlEncodedFormEntity(urlParameters));
            try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    InputStreamReader reader = new InputStreamReader(response.getEntity().getContent(),
                            StandardCharsets.UTF_8);
                    BufferedReader in = new BufferedReader(reader);
                    String json = in.readLine();
                    // Parse the Json response and retrieve the Access Token
                    Gson gson = new Gson();
                    JsonObject tokenDetails = gson.fromJson(json, JsonObject.class);
                    in.close();
                    LOG.info("Access Token Response: " + tokenDetails.get("access_token").toString());
                    return tokenDetails.get("access_token").toString();
                }
                throw new IOException("Error occurred while retrieving the access token. Status code: " +
                        response.getStatusLine().getStatusCode());
            }
        } catch (IOException e) {
            throw new RuntimeException("Error occurred while retrieving the access token.", e);
        }
    }

    private static void buildBasicAuthHeader(HttpRequestBase httpRequestBase, String clientId, String clientSecret) {

        String auth = clientId + ":" + clientSecret;
        byte[] encodedAuth = Base64.encodeBase64(auth.getBytes(StandardCharsets.UTF_8));
        httpRequestBase.setHeader(HttpHeaders.AUTHORIZATION, "Basic " +
                new String(encodedAuth, StandardCharsets.UTF_8));
    }
}
