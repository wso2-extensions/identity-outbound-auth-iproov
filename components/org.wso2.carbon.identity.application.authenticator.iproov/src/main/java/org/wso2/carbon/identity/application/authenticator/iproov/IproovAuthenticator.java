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
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.iproov.common.constants.IproovAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.iproov.common.exception.IproovAuthnFailedException;
import org.wso2.carbon.identity.application.authenticator.iproov.common.web.IproovAuthorizationAPIClient;
import org.wso2.carbon.identity.application.authenticator.iproov.internal.IproovAuthenticatorDataHolder;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
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

        return IproovAuthenticatorConstants.AUTHENTICATOR_NAME_VALUE;
    }

    @Override
    public String getFriendlyName() {

        return IproovAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME_VALUE;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();
        configProperties.add(getProperty(IproovAuthenticatorConstants.ConfigProperties.BASE_URL));
        configProperties.add(getProperty(IproovAuthenticatorConstants.ConfigProperties.OAUTH_USERNAME));
        configProperties.add(getProperty(IproovAuthenticatorConstants.ConfigProperties.OAUTH_PASSWORD));
        configProperties.add(getProperty(IproovAuthenticatorConstants.ConfigProperties.API_KEY));
        configProperties.add(getProperty(IproovAuthenticatorConstants.ConfigProperties.API_SECRET));

        return configProperties;
    }

    private Property getProperty(IproovAuthenticatorConstants.ConfigProperties configProperties) {

        Property property = new Property();
        property.setName(configProperties.getName());
        property.setDisplayName(configProperties.getDisplayName());
        property.setDescription(configProperties.getDescription());
        property.setDisplayOrder(configProperties.getDisplayOrder());
        property.setRequired(true);
        return property;
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
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context) throws AuthenticationFailedException {

        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else {
            if (context.getLastAuthenticatedUser() != null) {
                String scenario = request.getParameter("scenario");
                // In the initial request to launch iProov login page scenario will be set to null.
                if (IproovAuthenticatorConstants.Verification.AUTHENTICATION.equals(scenario)
                        || IproovAuthenticatorConstants.Verification.ENROLLMENT.equals(scenario)) {
                    processAuthenticationResponse(request, response, context);
                    return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
                }
                try {
                    boolean isUserIproovEnrolled = isUserIproovEnrolled(context.getLastAuthenticatedUser());
                    boolean enableProgressiveEnrollment = isIproovProgressiveEnrollmentEnabled(context
                            .getTenantDomain());
                    if (!isUserIproovEnrolled && !enableProgressiveEnrollment) {
                        return AuthenticatorFlowStatus.FAIL_COMPLETED;
                    }
                } catch (UserStoreException e) {
                    throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages
                            .RETRIEVING_USER_STORE_FAILURE, e);
                }
                initiateIproovAuthenticationRequest(response, context);
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Authenticated user is not found in the context.");
                }
                throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages
                        .NO_AUTHENTICATED_USER_FOUND_FROM_PREVIOUS_STEP);
            }
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
                    .addParameter(IproovAuthenticatorConstants.AUTHENTICATOR_NAME,
                            IproovAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME_VALUE)
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
                    IproovAuthenticatorConstants.ErrorMessages.IPROOV_REDIRECT_URL_BUILD_FAILURE, e);
        }
    }

    @SuppressWarnings({"CRLF_INJECTION_LOGS", "UNVALIDATED_REDIRECT"})
    private void initiateIproovAuthenticationRequest(HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUser;
        String userId;
        boolean isUserIProovEnrolled;

        try {
            authenticatedUser = getAuthenticatedUserFromContext(context);
            isUserIProovEnrolled = isUserIproovEnrolled(authenticatedUser);
            userId = resolveUserId(authenticatedUser);
            if (StringUtils.isBlank(userId)) {
                throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND);
            }
        } catch (UserIdNotFoundException e) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND);
        } catch (UserStoreException e) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.RETRIEVING_REG_USER_FAILURE);
        }

        String username = authenticatedUser.getUserName();

        // Extract the IProov configurations.
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String baseUrl = authenticatorProperties.get(IproovAuthenticatorConstants.ConfigProperties.BASE_URL.getName());
        String apiKey = authenticatorProperties.get(IproovAuthenticatorConstants.ConfigProperties.API_KEY.getName());
        String apiSecret = authenticatorProperties.get(IproovAuthenticatorConstants.ConfigProperties.API_SECRET
                .getName());
        String oauthUsername = authenticatorProperties.get(IproovAuthenticatorConstants.ConfigProperties.OAUTH_USERNAME
                .getName());
        String oauthPassword = authenticatorProperties.get(IproovAuthenticatorConstants.ConfigProperties.OAUTH_PASSWORD
                .getName());

        // Validate iProov configurable parameters.
        validateIproovConfiguration(baseUrl, apiKey, apiSecret, oauthUsername, oauthPassword);

        String verifyToken = null;
        String enrollToken = null;
        try {
            if (isUserIProovEnrolled) {
                verifyToken = IproovAuthorizationAPIClient.getToken(baseUrl,
                        IproovAuthenticatorConstants.TokenEndpoints.IPROOV_VERIFY_TOKEN_PATH, apiKey, apiSecret,
                        userId);

                // Create the ServiceURLBuilder instance.
                ServiceURLBuilder serviceURLBuilder = ServiceURLBuilder.create()
                        .addPath(IproovAuthenticatorConstants.IPROOV_LOGIN_PAGE)
                        .addParameter(IproovAuthenticatorConstants.VERIFY_TOKEN, verifyToken);

                // Get the absolute public URL and perform a secure redirection.
                String absolutePublicURL = serviceURLBuilder.build().getAbsolutePublicURL();
                response.sendRedirect(absolutePublicURL);

            } else {
                enrollToken = IproovAuthorizationAPIClient.getToken(baseUrl,
                        IproovAuthenticatorConstants.TokenEndpoints.IPROOV_ENROLL_TOKEN_PATH, apiKey, apiSecret,
                        userId);

                // Create the ServiceURLBuilder instance.
                ServiceURLBuilder serviceURLBuilder = ServiceURLBuilder.create()
                        .addPath(IproovAuthenticatorConstants.IPROOV_LOGIN_PAGE)
                        .addParameter(IproovAuthenticatorConstants.ENROLL_TOKEN, enrollToken);

                // Get the absolute public URL and perform a secure redirection.
                String absolutePublicURL = serviceURLBuilder.build().getAbsolutePublicURL();
                response.sendRedirect(absolutePublicURL);
            }

            context.setProperty(IproovAuthenticatorConstants.USER_ID, userId);
            context.setProperty(IproovAuthenticatorConstants.USERNAME, username);

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
        } catch (URLBuilderException | IOException e) {
            throw getIproovAuthnFailedException(
                    IproovAuthenticatorConstants.ErrorMessages.IPROOV_REDIRECT_URL_BUILD_FAILURE, e);
        }
    }

    private AuthenticatedUser getAuthenticatedUserFromContext(AuthenticationContext context)
            throws IproovAuthnFailedException {

        if (context.getSequenceConfig() != null) {
            Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
            // Loop through the authentication steps and find the authenticated user from the subject identifier step.
            if (stepConfigMap != null) {
                for (StepConfig stepConfig : stepConfigMap.values()) {
                    AuthenticatedUser user = stepConfig.getAuthenticatedUser();
                    if (stepConfig.isSubjectAttributeStep()) {
                        if (user == null) {
                            throw new IproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.
                                    USER_NOT_FOUND.getCode(),
                                    IproovAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND.getMessage());
                        }
                        AuthenticatedUser authenticatedUser = new AuthenticatedUser(user);
                        if (StringUtils.isBlank(authenticatedUser.toFullQualifiedUsername())) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Username can not be empty.");
                            }
                            throw new IproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.
                                    USER_NOT_FOUND.getCode(),
                                    IproovAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND.getMessage());
                        }
                        return authenticatedUser;
                    }
                }
            }
        }
        // If authenticated user cannot be found from the previous steps.
        throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages
                .NO_AUTHENTICATED_USER_FOUND_FROM_PREVIOUS_STEP);
    }


    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        AuthenticatedUser authenticatedUserFromContext = getAuthenticatedUserFromContext(context);

        String userId;
        String username = authenticatedUserFromContext.getUserName();
        try {
            userId = resolveUserId(authenticatedUserFromContext);
            if (StringUtils.isBlank(userId)) {
                throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND);
            }
        } catch (UserIdNotFoundException e) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND);
        } catch (UserStoreException e) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.RETRIEVING_REG_USER_FAILURE);
        }
        // Extract the IProov configurations.
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String baseUrl = authenticatorProperties.get(IproovAuthenticatorConstants.ConfigProperties.BASE_URL.getName());
        String apiKey = authenticatorProperties.get(IproovAuthenticatorConstants.ConfigProperties.API_KEY.getName());
        String apiSecret = authenticatorProperties.get(IproovAuthenticatorConstants.ConfigProperties.API_SECRET
                .getName());
        String oauthUsername = authenticatorProperties.get(IproovAuthenticatorConstants.ConfigProperties
                .OAUTH_USERNAME.getName());
        String oauthPassword = authenticatorProperties.get(IproovAuthenticatorConstants.ConfigProperties.OAUTH_PASSWORD
                .getName());

        String verificationMode = request.getParameter(IproovAuthenticatorConstants.SCENARIO);
        String isValidated;
        if (IproovAuthenticatorConstants.Verification.AUTHENTICATION.equals(verificationMode)) {
            String verifyToken = (String) context.getProperty(IproovAuthenticatorConstants.VERIFY_TOKEN);
            isValidated = IproovAuthorizationAPIClient.validateVerification(baseUrl,
                    IproovAuthenticatorConstants.TokenEndpoints.IPROOV_VALIDATE_VERIFICATION_PATH, apiKey, apiSecret,
                    userId, verifyToken);
        } else {
            String enrollToken = (String) context.getProperty(IproovAuthenticatorConstants.ENROLL_TOKEN);
            isValidated = IproovAuthorizationAPIClient.validateVerification(baseUrl,
                    IproovAuthenticatorConstants.TokenEndpoints.IPROOV_ENROLL_VERIFICATION_PATH, apiKey, apiSecret,
                    userId, enrollToken);
            if (!Boolean.parseBoolean(isValidated)) {
                IproovAuthorizationAPIClient.removeIproovUserProfile(baseUrl, apiKey, oauthUsername, oauthPassword,
                        userId);
            }
        }

        //Set the authenticated user.
        if (Boolean.parseBoolean(isValidated)) {
            context.setSubject(authenticatedUserFromContext);
            if (IproovAuthenticatorConstants.Verification.ENROLLMENT.equals(verificationMode)) {
                try {
                    UserStoreManager userStoreManager = getUserStoreManager(authenticatedUserFromContext);
                    Map<String, String> claims = new HashMap<>();
                    claims.put(IproovAuthenticatorConstants.IPROOV_ENROLLED_CLAIM, "true");
                    userStoreManager.setUserClaimValues(username, claims, null);
                } catch (UserStoreException | AuthenticationFailedException e) {
                    throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages
                            .IPROOV_SETTING_IPROOV_CLAIM_VALUE_FAILURE, e);
                }
            }
        } else {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages
                    .IPROOV_VERIFICATION_TOKEN_VALIDATING_FAILURE);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Successfully logged in the user " + userId);
        }
    }

    /**
     * Get user claim value.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return User claim value.
     * @throws AuthenticationFailedException If an error occurred while getting the claim value.
     */
    private boolean isUserIproovEnrolled(AuthenticatedUser authenticatedUser)
            throws AuthenticationFailedException, UserStoreException {

        UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
        try {
            Map<String, String> claimValues =
                    userStoreManager.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(
                                    authenticatedUser.toFullQualifiedUsername()),
                            new String[]{IproovAuthenticatorConstants.IPROOV_ENROLLED_CLAIM}, null);
            return Boolean.parseBoolean(claimValues.get(IproovAuthenticatorConstants.IPROOV_ENROLLED_CLAIM));
        } catch (UserStoreException e) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND, e);
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
                throw new UserStoreException("UserStoreManager is null");
            }
            if (StringUtils.isBlank(userStoreDomain) || PRIMARY_DEFAULT_DOMAIN_NAME.equals(userStoreDomain)) {
                return userStoreManager;
            }
            return ((AbstractUserStoreManager) userStoreManager).getSecondaryUserStoreManager(userStoreDomain);
        } catch (UserStoreException e) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.RETRIEVING_REG_USER_FAILURE,
                    e);
        }
    }

    /**
     * Get the UserRealm for the user given user.
     *
     * @param tenantDomain Tenant domain.
     * @return UserRealm.
     * @throws IproovAuthnFailedException If an error occurred while getting the UserRealm or Userstore.
     */
    private UserRealm getTenantUserRealm(String tenantDomain) throws IproovAuthnFailedException {

        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        UserRealm userRealm;
        try {
            userRealm = (IproovAuthenticatorDataHolder.getRealmService()).getTenantUserRealm(tenantId);
        } catch (UserStoreException e) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages
                            .RETRIEVING_USER_STORE_FAILURE, e);
        }
        if (userRealm == null) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages
                    .RETRIEVING_USER_REALM_FAILURE);
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

    private String resolveUserId(AuthenticatedUser authenticatedUserFromContext) throws AuthenticationFailedException,
            UserStoreException, UserIdNotFoundException {

        if (authenticatedUserFromContext.isFederatedUser()) {
            UserStoreManager userStoreManager = getUserStoreManager(authenticatedUserFromContext);
            Map<String, String> claimValues =
                    userStoreManager.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(
                                    authenticatedUserFromContext.toFullQualifiedUsername()),
                            new String[]{IproovAuthenticatorConstants.USER_ID_CLAIM}, null);
            return claimValues.get(IproovAuthenticatorConstants.USER_ID_CLAIM);
        }
        return authenticatedUserFromContext.getUserId();
    }

    private boolean isIproovProgressiveEnrollmentEnabled(String tenantDomain) throws AuthenticationFailedException {

        return Boolean.parseBoolean(
                getIproovAuthenticatorConfig(IproovAuthenticatorConstants.ConnectorConfig
                                .ENABLE_IPROOV_PROGRESSIVE_ENROLLMENT,
                        tenantDomain));
    }

    /**
     * Get fido authenticator config related to the given key.
     *
     * @param key          Authenticator config key.
     * @param tenantDomain Tenant domain.
     * @return Value associated with the given config key.
     * @throws IproovAuthnFailedException If an error occurred while getting th config value.
     */
    public static String getIproovAuthenticatorConfig(String key, String tenantDomain) throws
            IproovAuthnFailedException {

        try {
            Property[] connectorConfigs;
            IdentityGovernanceService governanceService =
                    IproovAuthenticatorDataHolder.getIdentityGovernanceService();
            connectorConfigs = governanceService.getConfiguration(new String[]{key}, tenantDomain);
            return connectorConfigs[0].getValue();
        } catch (IdentityGovernanceException e) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages
                    .RETRIEVING_AUTHENTICATOR_CONFIG_FAILURE, e);
        }
    }

    private static IproovAuthnFailedException getIproovAuthnFailedException(
            IproovAuthenticatorConstants.ErrorMessages errorMessages, Exception e) {

        return new IproovAuthnFailedException(errorMessages.getCode(), errorMessages.getMessage(), e);
    }

    private IproovAuthnFailedException getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages
                                                                             errorMessages) {

        return new IproovAuthnFailedException(errorMessages.getCode(), errorMessages.getMessage());
    }
}
