package org.wso2.carbon.identity.application.authenticator.iproov;

import edu.umd.cs.findbugs.annotations.SuppressWarnings;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.iproov.common.constants.IproovAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.iproov.common.exception.IproovAuthnFailedException;
import org.wso2.carbon.identity.application.authenticator.iproov.common.web.IproovAuthorizationAPIClient;
import org.wso2.carbon.identity.application.authenticator.iproov.internal.IproovAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.user.core.UserCoreConstants.PRIMARY_DEFAULT_DOMAIN_NAME;


/**
 * This class contains all the functional tasks handled by the authenticator with iProov IdP and WSO2 Identity Server.
 */
public class IproovAuthenticator extends AbstractApplicationAuthenticator implements FederatedApplicationAuthenticator {

    private static final Log LOG = LogFactory.getLog(IproovAuthenticator.class);

    @Override
    public String getName() {

        return IproovAuthenticatorConstants.AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return IproovAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();

        Property baseURL = new Property();
        baseURL.setName(IproovAuthenticatorConstants.BASE_URL);
        baseURL.setDisplayName("Base URL");
        baseURL.setRequired(true);
        baseURL.setDescription("Enter the base URL of your iProov server deployment.");
        baseURL.setDisplayOrder(1);
        configProperties.add(baseURL);

        Property oauthUsername = new Property();
        oauthUsername.setName(IproovAuthenticatorConstants.OAUTH_USERNAME);
        oauthUsername.setDisplayName("OAuth Username");
        oauthUsername.setRequired(true);
        oauthUsername.setDescription("Enter the OAuth username of your iProov server deployment.");
        oauthUsername.setDisplayOrder(2);
        configProperties.add(oauthUsername);

        Property oauthPassword = new Property();
        oauthPassword.setName(IproovAuthenticatorConstants.OAUTH_PASSWORD);
        oauthPassword.setDisplayName("OAuth Password");
        oauthPassword.setRequired(true);
        oauthPassword.setDescription("Enter the OAuth password of your iProov server deployment.");
        oauthPassword.setDisplayOrder(3);
        configProperties.add(oauthPassword);

        Property apiKey = new Property();
        apiKey.setName(IproovAuthenticatorConstants.API_KEY);
        apiKey.setDisplayName("API Key");
        apiKey.setRequired(true);
        apiKey.setDescription("Enter the API key of your iProov server deployment.");
        apiKey.setDisplayOrder(4);
        configProperties.add(apiKey);

        Property apiSecret = new Property();
        apiSecret.setName(IproovAuthenticatorConstants.SECRET);
        apiSecret.setDisplayName("API Secret");
        apiSecret.setRequired(true);
        apiSecret.setDescription("Enter the API secret of your iProov server deployment.");
        apiSecret.setDisplayOrder(5);
        configProperties.add(apiSecret);

        return configProperties;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) {

        String username = (String) context.getProperty(IproovAuthenticatorConstants.USERNAME);

        // Extract the IProov configurations.
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String baseUrl = authenticatorProperties.get(IproovAuthenticatorConstants.BASE_URL);
        String apiKey = authenticatorProperties.get(IproovAuthenticatorConstants.API_KEY);
        String apiSecret = authenticatorProperties.get(IproovAuthenticatorConstants.SECRET);
//        String oauthUsername = authenticatorProperties.get(IproovAuthenticatorConstants.OAUTH_USERNAME);
//        String oauthPassword = authenticatorProperties.get(IproovAuthenticatorConstants.OAUTH_PASSWORD);

        String verificationMode = request.getParameter("scenario");
        String isValidated;
        if ("VERIFY_AUTHENTICATION".equals(verificationMode)) {
            String verifyToken = (String) context.getProperty(IproovAuthenticatorConstants.VERIFY_TOKEN);
            isValidated = IproovAuthorizationAPIClient.validateVerification(baseUrl,
                    IproovAuthenticatorConstants.IPROOV_VALIDATE_VERIFICATION_PATH, apiKey, apiSecret,
                    username, verifyToken);
        } else {
            String enrollToken = (String) context.getProperty(IproovAuthenticatorConstants.ENROLL_TOKEN);
            isValidated = IproovAuthorizationAPIClient.validateVerification(baseUrl,
                    IproovAuthenticatorConstants.IPROOV_ENROLL_VERIFICATION_PATH, apiKey, apiSecret,
                    username, enrollToken);
        }

        //Set the authenticated user.
        if (Boolean.parseBoolean(isValidated)) {
            AuthenticatedUser authenticatedUser =
                    AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(username);
            context.setSubject(authenticatedUser);
        } else {
            throw new RuntimeException("Iproov authentication failed");
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Successfully logged in the user " + username);
        }
    }

    @Override
    public boolean canHandle(HttpServletRequest httpServletRequest) {

        return httpServletRequest.getParameter(IproovAuthenticatorConstants.SESSION_DATA_KEY) != null;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {

        String sessionDataKey = httpServletRequest.getParameter(IproovAuthenticatorConstants.SESSION_DATA_KEY);
        if (StringUtils.isNotBlank(sessionDataKey)) {
            return sessionDataKey;
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("A unique identifier cannot be issued for both Request and Response. " +
                        "ContextIdentifier is NULL.");
            }
            return null;
        }
    }

    @Override
    public void initiateAuthenticationRequest(HttpServletRequest httpServletRequest,
                                              HttpServletResponse httpServletResponse,
                                              AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {

        try {
            redirectIproovLoginPage(httpServletResponse, authenticationContext, null, null);
        } catch (AuthenticationFailedException e) {
            String errorMessage = "Error occurred when trying to redirect user to the login page.";
            throw new AuthenticationFailedException(errorMessage, e);
        }
    }

    @SuppressWarnings("UNVALIDATED_REDIRECT")
    private void redirectIproovLoginPage(HttpServletResponse response, AuthenticationContext context,
                                         IproovAuthenticatorConstants.AuthenticationStatus authenticationStatus,
                                         Map<String, String> queryParams) throws IproovAuthnFailedException {

        try {
            ServiceURLBuilder iproovLoginPageURLBuilder = ServiceURLBuilder.create()
                    .addPath(IproovAuthenticatorConstants.IPROOV_LOGIN_PAGE)
                    .addParameter(IproovAuthenticatorConstants.SESSION_DATA_KEY, context.getContextIdentifier())
                    .addParameter("AuthenticatorName", IproovAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME)
                    .addParameter(IproovAuthenticatorConstants.TENANT_DOMAIN, context.getTenantDomain());

            if (authenticationStatus != null) {
                iproovLoginPageURLBuilder.addParameter("status", String.valueOf(authenticationStatus.getName()));
                iproovLoginPageURLBuilder.addParameter(
                        "message", String.valueOf(authenticationStatus.getMessage()));
            }

            if (queryParams != null) {
                for (Map.Entry<String, String> entry : queryParams.entrySet()) {
                    iproovLoginPageURLBuilder.addParameter(entry.getKey(), entry.getValue());
                }
            }
            String iproovLoginPageURL = iproovLoginPageURLBuilder.build().getAbsolutePublicURL();
            response.sendRedirect(iproovLoginPageURL);

        } catch (IOException e) {
            throw getIproovAuthnFailedException(
                    IproovAuthenticatorConstants.ErrorMessages.AUTHENTICATION_FAILED_REDIRECTING_LOGIN_FAILURE, e);
        } catch (URLBuilderException e) {
            throw getIproovAuthnFailedException(
                    IproovAuthenticatorConstants.ErrorMessages.IPROOV_ACCESS_TOKEN_INVALID_FAILURE, e);
        }
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context) throws AuthenticationFailedException,
            LogoutFailedException {

        if (context.isLogoutRequest()) {
            // if the logout request comes, then no need to go through and complete the flow.
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;

        } else if (request.getParameterMap().containsKey(IproovAuthenticatorConstants.USERNAME)) {
            // if the login form submission request comes, then go through this flow.
            initiateIproovAuthenticationRequest(request, response, context);
            return AuthenticatorFlowStatus.INCOMPLETE;

        } else if (context.getProperty(IproovAuthenticatorConstants.AUTH_STATUS) != null) {
            // if intermediate authentication request comes, then go through this flow.
            String authStatus = (String) context.getProperty(IproovAuthenticatorConstants.AUTH_STATUS);

            if (IproovAuthenticatorConstants.AuthenticationStatus.COMPLETED.getName().equals(authStatus)) {
                processAuthenticationResponse(request, response, context);
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;

            } else if (IproovAuthenticatorConstants.AuthenticationStatus.PENDING.getName().equals(authStatus)) {
                redirectIproovLoginPage(response, context, IproovAuthenticatorConstants.AuthenticationStatus.PENDING,
                        null);
                return AuthenticatorFlowStatus.INCOMPLETE;

            } else if (IproovAuthenticatorConstants.AuthenticationStatus.CANCELED.getName().equals(authStatus)) {
                redirectIproovLoginPage(response, context, IproovAuthenticatorConstants.AuthenticationStatus.CANCELED,
                        null);
                return AuthenticatorFlowStatus.INCOMPLETE;

            } else if (IproovAuthenticatorConstants.AuthenticationStatus.FAILED.getName().equals(authStatus)) {
                redirectIproovLoginPage(response, context, IproovAuthenticatorConstants.AuthenticationStatus.FAILED,
                        null);
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
        } else {
            if (context.getLastAuthenticatedUser() != null) {
                // If the user is already authenticated, initiate iProov authentication request.
                initiateIproovAuthenticationRequest(request, response, context);
            } else if ("VERIFY_AUTHENTICATION".equals(request.getParameter("scenario")) ||
                    "ENROLL_IPROOV".equals(request.getParameter("scenario"))) {
                // If the user is not authenticated, redirect to the iProov login page to prompt username.
                processAuthenticationResponse(request, response, context);
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            } else {
                initiateAuthenticationRequest(request, response, context);
            }
            return AuthenticatorFlowStatus.INCOMPLETE;
        }

        return super.process(request, response, context);
    }

    @SuppressWarnings(value = "CRLF_INJECTION_LOGS", justification = "username should be sanitized at this point.")
    private void initiateIproovAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                     AuthenticationContext context) throws AuthenticationFailedException {

        String username = null;
        if (context.getSequenceConfig() != null) {
            Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
            // loop through the authentication steps and find the authenticated user from the subject identifier step.
            if (stepConfigMap != null) {
                for (StepConfig stepConfig : stepConfigMap.values()) {
                    if (stepConfig.isSubjectIdentifierStep() && stepConfig.getAuthenticatedUser() != null) {
                        username = stepConfig.getAuthenticatedUser().getUserName();
                        break;
                    }
                }
            }
        }

        if (StringUtils.isEmpty(username)) {
            username = request.getParameter(IproovAuthenticatorConstants.USERNAME);
        }

        // Extract the IProov configurations.
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String baseUrl = authenticatorProperties.get(IproovAuthenticatorConstants.BASE_URL);
        String apiKey = authenticatorProperties.get(IproovAuthenticatorConstants.API_KEY);
        String apiSecret = authenticatorProperties.get(IproovAuthenticatorConstants.SECRET);
        String oauthUsername = authenticatorProperties.get(IproovAuthenticatorConstants.OAUTH_USERNAME);
        String oauthPassword = authenticatorProperties.get(IproovAuthenticatorConstants.OAUTH_PASSWORD);

        // Validate username and the iProov configurable parameters.
        if (StringUtils.isBlank(username)) {
            redirectIproovLoginPage(response, context,
                    IproovAuthenticatorConstants.AuthenticationStatus.INVALID_REQUEST, null);
            return;
        }
        validateIproovConfiguration(baseUrl, apiKey, apiSecret, oauthUsername, oauthPassword);

        String verifyToken = null;
        String enrollToken = null;
        try {
            if (isIproovUserExist(username, context)) {

                verifyToken = IproovAuthorizationAPIClient.getToken(baseUrl,
                        IproovAuthenticatorConstants.IPROOV_VERIFY_TOKEN_PATH, apiKey, apiSecret, username);
                response.sendRedirect(ServiceURLBuilder.create().addPath(
                                "/authenticationendpoint/iproovlogin.jsp")
                        .addParameter("verifyToken", verifyToken).build().getAbsolutePublicURL());
                LOG.info("verifyToken: " + verifyToken);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Successfully validated the user " + username);
                }


            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("User " + username + " does not exist in iProov.");
                }

                enrollToken = IproovAuthorizationAPIClient.getToken(baseUrl,
                        IproovAuthenticatorConstants.IPROOV_ENROLL_TOKEN_PATH, apiKey, apiSecret, username);
                response.sendRedirect(ServiceURLBuilder.create().addPath(
                                "/authenticationendpoint/iproovlogin.jsp")
                        .addParameter("enrollToken", enrollToken).build().getAbsolutePublicURL());
                LOG.info("verifyToken: " + enrollToken);
            }
//            RegisteredDevicesResponse registeredDevicesResponse =
//            HYPRAuthorizationAPIClient.getRegisteredDevicesRequest(baseUrl, appId, apiToken, username);
//
//            // If an empty array received for the registered devices redirect user back to the login page and
//            // display "Invalid username" since a HYPR user cannot exist without a set of registered devices.
//            if (registeredDevicesResponse.getRegisteredDevices().isEmpty()) {
//                // If HYPR is used as a 2nd factor, disabling the username field and login button in login page
//                if (context.getCurrentStep() == 1) {
//                    redirectHYPRLoginPage(response, context, HYPR.AuthenticationStatus.INVALID_REQUEST);
//                } else {
//                    redirectHYPRLoginPage(response, context, HYPR.AuthenticationStatus.INVALID_USER);
//                }
//                return;
//            }
//
//
//            if (LOG.isDebugEnabled()) {
//                LOG.debug("Successfully retrieved the registered devices for the user ");
//            }
//
//            // Extract the user specific machineId which is a unique ID across all the registered devices under a
//            // particular unique username.
//            String machineId = registeredDevicesResponse.getRegisteredDevices().get(0).getMachineId();
//
//            if (StringUtils.isBlank(machineId)) {
//                if (LOG.isDebugEnabled()) {
//                    LOG.debug("Retrieved machine ID for the user " + maskedUsername + " is either null or empty.");
//                }
//                redirectHYPRLoginPage(response, context, HYPR.AuthenticationStatus.FAILED);
//                return;
//            }
//
//            // Send a push notification and extract the requestId received from the HYPR server.
//            DeviceAuthenticationResponse deviceAuthenticationResponse =
//                    HYPRAuthorizationAPIClient.initiateAuthenticationRequest(
//                            baseUrl, appId, apiToken, username, machineId);
//            String requestId = deviceAuthenticationResponse.getResponse().getRequestId();
//
//            if (StringUtils.isBlank(requestId)) {
//                if (LOG.isDebugEnabled()) {
//                    LOG.debug("Retrieved request ID for the authentication request for the user " + maskedUsername +
//                            " is either null or empty.");
//                }
//                redirectHYPRLoginPage(response, context, HYPR.AuthenticationStatus.FAILED);
//                return;
//            }
//
//            if (LOG.isDebugEnabled()) {
//                LOG.debug("Successfully sent a push notification for the registered devices of the user " +
//                        maskedUsername);
//            }
//
            // Store the iProov context information.
//            context.setProperty(HYPR.AUTH_REQUEST_ID, requestId);
            context.setProperty(IproovAuthenticatorConstants.USERNAME, username);
//
//            // Inform the user that the push notification has been sent to the registered device.
            Map<String, String> queryParams = new HashMap<>();
            if (verifyToken != null) {
                context.setProperty(IproovAuthenticatorConstants.VERIFY_TOKEN, verifyToken);
                queryParams.put(IproovAuthenticatorConstants.VERIFY_TOKEN, verifyToken);
            }
            if (enrollToken != null) {
                context.setProperty(IproovAuthenticatorConstants.ENROLL_TOKEN, enrollToken);
                queryParams.put(IproovAuthenticatorConstants.ENROLL_TOKEN, enrollToken);
            }
            redirectIproovLoginPage(response, context, IproovAuthenticatorConstants.AuthenticationStatus.PENDING,
                    queryParams);

        } catch (IproovAuthnFailedException e) {
            // Handle invalid or expired token.
            if (IproovAuthenticatorConstants.ErrorMessages.IPROOV_ACCESS_TOKEN_INVALID_FAILURE.getCode().equals(
                    e.getErrorCode())) {
                LOG.error(e.getErrorCode() + " : " + e.getMessage());
                redirectIproovLoginPage(response, context, IproovAuthenticatorConstants.
                        AuthenticationStatus.INVALID_TOKEN, null);
            } else {
                throw new AuthenticationFailedException(e.getMessage(), e);
            }
        } catch (URLBuilderException | IOException | UserStoreException e) {
            throw new RuntimeException(e);
        }
    }

    private boolean isIproovUserExist(String username, AuthenticationContext context) throws
            AuthenticationFailedException, UserStoreException {

        String tenantDomain = context.getTenantDomain();

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(username);
        authenticatedUser.setTenantDomain(tenantDomain);

        String isIproovEnrolled = isUserIproovEnrolled(authenticatedUser, tenantDomain, context,
                false);
        return Boolean.parseBoolean(isIproovEnrolled);
    }

    /**
     * Resolve the mobile number of the authenticated user.
     *
     * @param user                       Authenticated user.
     * @param tenantDomain               Application tenant domain.
     * @param context                    AuthenticationContext.
     * @param isInitialFederationAttempt Whether auth attempt by a not JIT provisioned federated user.
     * @return Mobile number of the authenticated user.
     * @throws AuthenticationFailedException If an error occurred while resolving the mobile number.
     */
    private String isUserIproovEnrolled(AuthenticatedUser user, String tenantDomain,
                                        AuthenticationContext context, boolean isInitialFederationAttempt)
            throws AuthenticationFailedException, UserStoreException {

        String isUserIproovEnrolled = null;
        if (isInitialFederationAttempt) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Getting the mobile number of the initially federating user: %s",
                        user.getUserName()));
            }
//            mobile = getMobileNoForFederatedUser(user, tenantDomain, context);
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format("Getting the mobile number of the local user: %s in user store: %s in " +
                        "tenant: %s", user.getUserName(), user.getUserStoreDomain(), user.getTenantDomain()));
            }
            isUserIproovEnrolled = getUserClaimValueFromUserStore(user, context);
        }
        return isUserIproovEnrolled;
    }

    /**
     * Get user claim value.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return User claim value.
     * @throws AuthenticationFailedException If an error occurred while getting the claim value.
     */
    private String getUserClaimValueFromUserStore(AuthenticatedUser authenticatedUser , AuthenticationContext context)
            throws AuthenticationFailedException, UserStoreException {

        UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
        try {
            Map<String, String> claimValues =
                    userStoreManager.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(
                                    authenticatedUser.toFullQualifiedUsername()),
                            new String[]{"http://wso2.org/claims/iproovEnrolled"}, null);
            return claimValues.get("http://wso2.org/claims/iproovEnrolled");
        } catch (UserStoreException e) {
            // User not found exception
            throw new UserStoreException();
        }
    }
    /**
     * Get UserStoreManager for the given user.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return UserStoreManager.
     * @throws AuthenticationFailedException If an error occurred while getting the UserStoreManager.
     */
    private UserStoreManager getUserStoreManager(AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException, UserStoreException {

        UserRealm userRealm = getTenantUserRealm(authenticatedUser.getTenantDomain());
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        try {
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            if (userStoreManager == null) {
            }
            if (StringUtils.isBlank(userStoreDomain) || PRIMARY_DEFAULT_DOMAIN_NAME.equals(userStoreDomain)) {
                return userStoreManager;
            }
            return ((AbstractUserStoreManager) userStoreManager).getSecondaryUserStoreManager(userStoreDomain);
        } catch (UserStoreException e) {
            throw new RuntimeException();
        }
    }


    /**
     * Get the UserRealm for the user given user.
     *
     * @param tenantDomain Tenant domain.
     * @return UserRealm.
     * @throws AuthenticationFailedException If an error occurred while getting the UserRealm.
     */
    private UserRealm getTenantUserRealm(String tenantDomain) throws AuthenticationFailedException, UserStoreException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        UserRealm userRealm;
        try {
            userRealm = (IproovAuthenticatorDataHolder.getRealmService()).getTenantUserRealm(tenantId);
        } catch (UserStoreException e) {
            throw new UserStoreException();
        }
        if (userRealm == null) {
            throw new UserStoreException();
        }
        return userRealm;
    }

    private void validateIproovConfiguration(String baseUrl, String apiKey, String apiSecret, String oauthUsername,
                                             String oauthPassword) throws IproovAuthnFailedException {

        if (StringUtils.isBlank(baseUrl)) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.
                    IPROOV_BASE_URL_INVALID_FAILURE);
        }

        if (StringUtils.isBlank(apiKey)) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.
                    IPROOV_API_KEY_INVALID_FAILURE);
        }
        if (StringUtils.isBlank(apiSecret)) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.
                    IPROOV_API_SECRET_INVALID_FAILURE);
        }

        if (StringUtils.isBlank(oauthUsername)) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.
                    IPROOV_OAUTH_USERNAME_INVALID_FAILURE);
        }

        if (StringUtils.isBlank(oauthPassword)) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.
                    IPROOV_OAUTH_PASSWORD_INVALID_FAILURE);
        }
    }

    private IproovAuthnFailedException getIproovAuthnFailedException(
            IproovAuthenticatorConstants.ErrorMessages errorMessages, Exception e) {

        return new IproovAuthnFailedException(errorMessages.getCode(), errorMessages.getMessage(), e);
    }

    private IproovAuthnFailedException getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages
                                                                             errorMessages) {

        return new IproovAuthnFailedException(errorMessages.getCode(), errorMessages.getMessage());
    }
}
