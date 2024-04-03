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

package org.wso2.carbon.identity.application.authenticator.iproov;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.iproov.common.constants.IproovAuthenticatorConstants;
import org.wso2.carbon.identity.application.common.model.Property;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

/**
 * Unit tests for IproovAuthenticator class.
 */
public class IproovAuthenticatorTest {

    private static final String sessionDataKey = "testSessionKey";

    private IproovAuthenticator iproovAuthenticator;

    private AutoCloseable autoCloseable;

    @Mock
    private HttpServletRequest httpServletRequest;

    @Mock
    private IproovAuthenticator mockedIproovAuthenticator;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Mock
    private AuthenticatedUser mockedAuthenticatedUser;

    @Spy
    private AuthenticationContext context;

    @Spy
    private IproovAuthenticator spy;

    @BeforeClass
    public void setUp() {

        autoCloseable = MockitoAnnotations.openMocks(this);
        iproovAuthenticator = new IproovAuthenticator();
    }

    @AfterClass
    public void close() throws Exception {

        autoCloseable.close();
    }

    @Test(description = "Test for getName method")
    public void testTestGetName() {

        Assert.assertEquals(iproovAuthenticator.getName(), IproovAuthenticatorConstants.AUTHENTICATOR_NAME_VALUE);
    }

    @Test(description = "Test for getFriendlyName method")
    public void testGetFriendlyName() {

        Assert.assertEquals(iproovAuthenticator.getFriendlyName(), IproovAuthenticatorConstants.
                AUTHENTICATOR_FRIENDLY_NAME_VALUE);
    }

    @Test(description = "Test for getConfigurationProperties method")
    public void testGetConfigurationProperties() {

        List<Property> propertyList = iproovAuthenticator.getConfigurationProperties();
        for (IproovAuthenticatorConstants.ConfigProperties prop :
                IproovAuthenticatorConstants.ConfigProperties.values()) {
            Property property = propertyList.stream()
                    .filter(p -> p.getName().equals(prop.getName()))
                    .findFirst().orElse(null);
            Assert.assertNotNull(property);
            Assert.assertEquals(prop.getName(), property.getName());
            Assert.assertEquals(prop.getDisplayName(), property.getDisplayName());
            Assert.assertEquals(prop.getDescription(), property.getDescription());
            Assert.assertEquals(prop.getDisplayOrder(), property.getDisplayOrder());
            Assert.assertTrue(property.isRequired());
        }
    }

    @Test(description = "Test for canHandle method")
    public void testCanHandle() {

        when(httpServletRequest.getParameter(IproovAuthenticatorConstants.SESSION_DATA_KEY))
                .thenReturn(sessionDataKey);
        Assert.assertTrue(iproovAuthenticator.canHandle(httpServletRequest));

        when(httpServletRequest.getParameter(IproovAuthenticatorConstants.SESSION_DATA_KEY)).thenReturn(null);
        Assert.assertFalse(iproovAuthenticator.canHandle(httpServletRequest));
    }

    @Test(description = "Test for getContextIdentifier method")
    public void testGetContextIdentifier() {

        when(httpServletRequest.getParameter("sessionDataKey")).thenReturn(sessionDataKey);
        Assert.assertEquals(iproovAuthenticator.getContextIdentifier(httpServletRequest), sessionDataKey);

        when(httpServletRequest.getParameter("sessionDataKey")).thenReturn(null);
        Assert.assertNull(iproovAuthenticator.getContextIdentifier(httpServletRequest));
    }

    @Test(description = "Test for initiateAuthenticationRequest method")
    public void testProcessWithStatusCompletedWithAuthentication() throws AuthenticationFailedException {

        doReturn(true).when(mockedIproovAuthenticator).canHandle(httpServletRequest);

        setAuthenticatedUser();
        mockHttpServletRequest("authentication");
        doNothing().when(spy).processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
        AuthenticatorFlowStatus status = spy.process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    private void setAuthenticatedUser() {

        when(mockedAuthenticatedUser.toFullQualifiedUsername()).thenReturn("testUser@testDomain");
        when(mockedAuthenticatedUser.getUserName()).thenReturn("testUser");
        when(mockedAuthenticatedUser.getTenantDomain()).thenReturn("testDomain");
        when(mockedAuthenticatedUser.getUserStoreDomain()).thenReturn("testUserStoreDomain");

        when(context.getProperty(IproovAuthenticatorConstants.AUTHENTICATED_USER)).thenReturn(mockedAuthenticatedUser);
        when(context.getLastAuthenticatedUser()).thenReturn(mockedAuthenticatedUser);
        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatedUser(mockedAuthenticatedUser);
        stepConfig.setSubjectAttributeStep(true);
        Map<Integer, StepConfig> stepConfigMap = new HashMap<>();
        stepConfigMap.put(1, stepConfig);
        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepConfigMap);
        when(context.getSequenceConfig()).thenReturn(sequenceConfig);
    }
    @Test(description = "Test for initiateAuthenticationRequest method")
    public void testProcessWithStatusCompletedWithVerification() throws AuthenticationFailedException {

        doReturn(true).when(mockedIproovAuthenticator).canHandle(httpServletRequest);

        setAuthenticatedUser();
        mockHttpServletRequest("enrollment");
        doNothing().when(spy).processAuthenticationResponse(httpServletRequest, httpServletResponse, context);
        AuthenticatorFlowStatus status = spy.process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test(description = "Test for initiateAuthenticationRequest method")
    public void testProcessWithStatusIncompleteWithRetry() throws Exception {

        doReturn(true).when(mockedIproovAuthenticator).canHandle(httpServletRequest);

        setAuthenticatedUser();
        mockHttpServletRequest("retry");
        doNothing().when(spy).initiateIproovAuthenticationRequest(httpServletRequest, httpServletResponse, context);
        AuthenticatorFlowStatus status = spy.process(httpServletRequest, httpServletResponse, context);
        Assert.assertEquals(status, AuthenticatorFlowStatus.INCOMPLETE);
    }

    private void mockHttpServletRequest(String scenario) {

        when(httpServletRequest.getParameter(IproovAuthenticatorConstants.SESSION_DATA_KEY))
                .thenReturn(sessionDataKey);
        when(httpServletRequest.getParameter(IproovAuthenticatorConstants.SCENARIO))
                .thenReturn(scenario);
    }
}
