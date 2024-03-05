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

package org.wso2.carbon.identity.application.authenticator.iproov.common.web;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.StatusLine;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.util.EntityUtils;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Unit tests for IproovAuthorizationAPIClient class.
 */
public class IproovAuthorizationAPIClientTest {

    @Mock
    private URIBuilder mockedURIBuilder;

    @Mock
    private HttpResponse mockedHttpResponse;

    @Mock
    private StatusLine mockedStatusLine;

    @Mock
    private HttpEntity mockedHttpEntity;

    private IproovAuthorizationAPIClient iproovAuthorizationAPIClient;
    private MockedStatic<IproovWebUtils> mockedIproovWebUtils;
    private MockedStatic<EntityUtils> mockedEntityUtils;
    private AutoCloseable autoCloseable;

    // Mocking dependencies.
    String baseUrl = "http://example.com";
    String tokenPath = "/token";
    String apiKey = "apiKey";
    String clientId = "clientId";
    String secret = "secret";
    String userId = "userId";
    String token = "tokenString";

    @BeforeClass
    public void setUp() {

        autoCloseable = MockitoAnnotations.openMocks(this);
        iproovAuthorizationAPIClient = new IproovAuthorizationAPIClient();
        mockedIproovWebUtils = mockStatic(IproovWebUtils.class);
        mockedEntityUtils = mockStatic(EntityUtils.class);

    }

    @AfterClass
    public void close() throws Exception {

        mockedIproovWebUtils.close();
        mockedEntityUtils.close();
        autoCloseable.close();
    }



    @Test(description = "Test for getToken method")
    public void testGetToken() throws Exception {

        when(mockedURIBuilder.setPath(tokenPath)).thenReturn(mockedURIBuilder);
        when(mockedURIBuilder.build()).thenReturn(new java.net.URI(baseUrl + tokenPath));

        when(mockedHttpResponse.getStatusLine()).thenReturn(mockedStatusLine);
        when(mockedHttpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);

        mockedIproovWebUtils.when(() -> IproovWebUtils.httpPost(any(), any(), eq(apiKey), eq(secret))).
                thenReturn(mockedHttpResponse);
        when(mockedHttpResponse.getEntity()).thenReturn(mockedHttpEntity);
        String jsonString = "{\"token\":\"tokenString\"}";
        mockedEntityUtils.when(() -> EntityUtils.toString(mockedHttpEntity)).thenReturn(jsonString);

        // Test getToken method
        String token = iproovAuthorizationAPIClient.getToken(baseUrl, tokenPath, apiKey, secret, userId);
        Assert.assertEquals("tokenString", token);
    }

    @Test(description = "Test for validateVerification method")
    public void testValidateVerification() throws Exception {

        when(mockedURIBuilder.setPath(tokenPath)).thenReturn(mockedURIBuilder);
        when(mockedURIBuilder.build()).thenReturn(new java.net.URI(baseUrl + tokenPath));

        when(mockedHttpResponse.getStatusLine()).thenReturn(mockedStatusLine);
        when(mockedHttpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);

        mockedIproovWebUtils.when(() -> IproovWebUtils.httpPost(any(), any(), eq(apiKey), eq(secret))).
                thenReturn(mockedHttpResponse);
        when(mockedHttpResponse.getEntity()).thenReturn(mockedHttpEntity);

        String passedTrue = "{\"passed\":\"true\"}";
        mockedEntityUtils.when(() -> EntityUtils.toString(mockedHttpEntity)).thenReturn(passedTrue);

        // Test getToken method
        boolean passed = iproovAuthorizationAPIClient.validateVerification(baseUrl, tokenPath, apiKey, secret, userId,
                token);
        Assert.assertTrue(passed);

        String passedFalse = "{\"passed\":\"false\"}";
        when(EntityUtils.toString(mockedHttpEntity)).thenReturn(passedFalse);

        // Test getToken method
        boolean failed = iproovAuthorizationAPIClient.validateVerification(baseUrl, tokenPath, apiKey, secret, userId,
                token);
        Assert.assertFalse(failed);
    }

    @Test(description = "Test for removeIproovUserProfile method")
    public void testRemoveIproovUserProfile() throws Exception {

        when(mockedURIBuilder.setPath(tokenPath)).thenReturn(mockedURIBuilder);
        when(mockedURIBuilder.build()).thenReturn(new java.net.URI(baseUrl + tokenPath));

        when(mockedHttpResponse.getStatusLine()).thenReturn(mockedStatusLine);
        when(mockedHttpResponse.getStatusLine().getStatusCode()).thenReturn(HttpStatus.SC_OK);

        mockedIproovWebUtils.when(() -> IproovWebUtils.httpDelete(any(), any(), eq(apiKey), eq(clientId), eq(secret))).
                thenReturn(mockedHttpResponse);
        when(mockedHttpResponse.getEntity()).thenReturn(mockedHttpEntity);

        String status = "{\"status\":\"Deleted\"}";
        mockedEntityUtils.when(() -> EntityUtils.toString(mockedHttpEntity)).thenReturn(status);
        boolean removedProfile = iproovAuthorizationAPIClient.removeIproovUserProfile(baseUrl, apiKey, clientId,
                secret, userId);

        Assert.assertTrue(removedProfile);
    }
}
