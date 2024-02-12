package org.wso2.carbon.identity.application.authenticator.iproov.common.web;

import org.apache.commons.lang.ArrayUtils;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.wso2.carbon.identity.application.authenticator.iproov.common.constants.IproovAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.iproov.common.exception.IproovAuthenticatorClientException;

import java.io.IOException;

import static java.util.Objects.isNull;

/**
 * HTTP client manager.
 */
public class HttpClientManager {

    private static final int HTTP_CONNECTION_TIMEOUT = 3000;
    private static final int HTTP_READ_TIMEOUT = 3000;
    private static final int HTTP_CONNECTION_REQUEST_TIMEOUT = 3000;
    private static final int DEFAULT_MAX_CONNECTIONS = 20;
    private static volatile HttpClientManager httpClientManagerInstance;
    private final CloseableHttpClient httpClient;

    /**
     * Creates a client manager.
     *
     * @throws IproovAuthenticatorClientException Exception thrown when an error occurred when creating HTTP client.
     */
    private HttpClientManager() throws IproovAuthenticatorClientException {

        PoolingHttpClientConnectionManager connectionManager;
        try {
            connectionManager = createPoolingConnectionManager();
        } catch (IOException e) {
            throw handleServerException(
                    IproovAuthenticatorConstants.ErrorMessages.AUTHENTICATION_FAILED_REDIRECTING_LOGIN_FAILURE, e);
        }

        RequestConfig config = createRequestConfig();
        httpClient = HttpClients.custom()
                .setDefaultRequestConfig(config)
                .setConnectionManager(connectionManager).build();
    }

    /**
     * Returns an instance of the HttpClientManager.
     *
     * @throws IproovAuthenticatorClientException Exception thrown when an error occurred when creating HTTP client.
     */
    public static HttpClientManager getInstance() throws IproovAuthenticatorClientException {

        if (httpClientManagerInstance == null) {
            synchronized (HttpClientManager.class) {
                if (httpClientManagerInstance == null) {
                    httpClientManagerInstance = new HttpClientManager();
                }
            }
        }
        return httpClientManagerInstance;
    }

    /**
     * Get HTTP client.
     *
     * @return CloseableHttpClient instance.
     * @throws IproovAuthenticatorClientException Exception thrown when an error occurred when getting HTTP client.
     */
    public CloseableHttpClient getHttpClient() throws IproovAuthenticatorClientException {

        if (isNull(httpClient)) {
            throw handleServerException(
                    IproovAuthenticatorConstants.ErrorMessages.AUTHENTICATION_FAILED_REDIRECTING_LOGIN_FAILURE, null);
        }
        return httpClient;
    }

    private RequestConfig createRequestConfig() {

        return RequestConfig.custom()
                .setConnectTimeout(HTTP_CONNECTION_TIMEOUT)
                .setConnectionRequestTimeout(HTTP_CONNECTION_REQUEST_TIMEOUT)
                .setSocketTimeout(HTTP_READ_TIMEOUT)
                .setRedirectsEnabled(false)
                .setRelativeRedirectsAllowed(false)
                .build();
    }

    private PoolingHttpClientConnectionManager createPoolingConnectionManager() throws IOException {

        PoolingHttpClientConnectionManager poolingHttpClientConnectionMgr = new PoolingHttpClientConnectionManager();
        // Increase max total connection to 20.
        poolingHttpClientConnectionMgr.setMaxTotal(DEFAULT_MAX_CONNECTIONS);
        // Increase default max connection per route to 20.
        poolingHttpClientConnectionMgr.setDefaultMaxPerRoute(DEFAULT_MAX_CONNECTIONS);
        return poolingHttpClientConnectionMgr;
    }

    private static IproovAuthenticatorClientException handleServerException(
            IproovAuthenticatorConstants.ErrorMessages error, Throwable throwable, String... data) {

        String description = error.getDescription();
        if (ArrayUtils.isNotEmpty(data)) {
            description = String.format(description, data);
        }
        return new IproovAuthenticatorClientException(error.getMessage(), description, error.getCode(), throwable);
    }
}
