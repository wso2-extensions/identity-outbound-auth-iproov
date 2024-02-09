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
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
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

import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.OPERATION_STATUS;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;
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
        configProperties.add(getProperty(IproovAuthenticatorConstants.ConfigProperties.ENABLE_PROGRESSIVE_ENROLLMENT));
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

        try {
            if (context.isLogoutRequest()) {
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
            if (context.getLastAuthenticatedUser() == null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Authenticated user is not found in the context.");
                }
                throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages
                        .NO_AUTHENTICATED_USER_FOUND_FROM_PREVIOUS_STEP);
            }
            String scenario = request.getParameter("scenario");
            // In the initial request to launch iProov login page scenario will be set to null.
            if (IproovAuthenticatorConstants.Verification.AUTHENTICATION.equals(scenario)
                    || IproovAuthenticatorConstants.Verification.ENROLLMENT.equals(scenario)) {
                processAuthenticationResponse(request, response, context);
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
            if (IproovAuthenticatorConstants.Verification.RETRY.equals(scenario)) {
                initiateIproovAuthenticationRequest(request, response, context);
                return AuthenticatorFlowStatus.INCOMPLETE;
            }
            boolean isUserIproovEnrolled = Boolean.parseBoolean(getClaimValue(
                    context.getLastAuthenticatedUser(), IproovAuthenticatorConstants.IPROOV_ENROLLED_CLAIM));
            boolean enableProgressiveEnrollment = isIproovProgressiveEnrollmentEnabled(context);
            if (!isUserIproovEnrolled && !enableProgressiveEnrollment) {
                return AuthenticatorFlowStatus.FAIL_COMPLETED;
            }
            initiateIproovAuthenticationRequest(request, response, context);

            return AuthenticatorFlowStatus.INCOMPLETE;


        } catch (UserStoreException e) {
            throw getIproovAuthnFailedException(
                    IproovAuthenticatorConstants.ErrorMessages.RETRIEVING_USER_STORE_FAILURE, e);
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
    private void initiateIproovAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                     AuthenticationContext context) throws
            AuthenticationFailedException, UserStoreException {

        AuthenticatedUser authenticatedUser;
        String userId;
        boolean isUserIProovEnrolled;

        try {
            authenticatedUser = getAuthenticatedUserFromContext(context);
            isUserIProovEnrolled = Boolean.parseBoolean(getClaimValue(authenticatedUser,
                    IproovAuthenticatorConstants.IPROOV_ENROLLED_CLAIM));
            userId = resolveUserId(authenticatedUser);

            if (StringUtils.isBlank(userId)) {
                throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND);
            }

            boolean isUserAccountLocked = Boolean.parseBoolean(getClaimValue(authenticatedUser,
                    IproovAuthenticatorConstants.USER_ACCOUNT_LOCKED_CLAIM));
            if (isUserAccountLocked) {
                LOG.error("User account is locked.");
                throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.USER_ACCOUNT_LOCKED);
            }

            String username = authenticatedUser.getUserName();

            // Extract the IProov configurations.
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String baseUrl = authenticatorProperties.get(
                    IproovAuthenticatorConstants.ConfigProperties.BASE_URL.getName());
            String apiKey = authenticatorProperties.get(
                    IproovAuthenticatorConstants.ConfigProperties.API_KEY.getName());
            String apiSecret = authenticatorProperties.get(
                    IproovAuthenticatorConstants.ConfigProperties.API_SECRET.getName());
            String oauthUsername = authenticatorProperties.get(
                    IproovAuthenticatorConstants.ConfigProperties.OAUTH_USERNAME.getName());
            String oauthPassword = authenticatorProperties.get(
                    IproovAuthenticatorConstants.ConfigProperties.OAUTH_PASSWORD.getName());

            // Validate iProov configurable parameters.
            validateIproovConfiguration(baseUrl, apiKey, apiSecret, oauthUsername, oauthPassword);

            String verifyToken = null;
            String enrollToken = null;
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
            if (IproovAuthenticatorConstants.Verification.RETRY.equals(request.getParameter("scenario"))) {
                queryParams.put(IproovAuthenticatorConstants.Verification.RETRY, "true");
                handleIProovFailedAttempts(authenticatedUser);
            }
            redirectIproovLoginPage(response, context, IproovAuthenticatorConstants.AuthenticationStatus.PENDING,
                    queryParams);

        } catch (IproovAuthnFailedException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (URLBuilderException | IOException e) {
            throw getIproovAuthnFailedException(
                    IproovAuthenticatorConstants.ErrorMessages.IPROOV_REDIRECT_URL_BUILD_FAILURE, e);
        } catch (UserIdNotFoundException e) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND);
        } catch (UserStoreException e) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.RETRIEVING_REG_USER_FAILURE);
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

        boolean isUserAccountLocked;
        try {
            isUserAccountLocked = Boolean.parseBoolean(getClaimValue(authenticatedUserFromContext,
                    IproovAuthenticatorConstants.USER_ACCOUNT_LOCKED_CLAIM));

            if (isUserAccountLocked) {
                LOG.error("User account is locked.");
                throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.USER_ACCOUNT_LOCKED);
            }

            String userId;
            String username = authenticatedUserFromContext.getUserName();
            userId = resolveUserId(authenticatedUserFromContext);
            if (StringUtils.isBlank(userId)) {
                throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND);
            }

            // Extract the IProov configurations.
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String baseUrl = authenticatorProperties.get(
                    IproovAuthenticatorConstants.ConfigProperties.BASE_URL.getName());
            String apiKey = authenticatorProperties.get(
                    IproovAuthenticatorConstants.ConfigProperties.API_KEY.getName());
            String apiSecret = authenticatorProperties.get(
                    IproovAuthenticatorConstants.ConfigProperties.API_SECRET.getName());
            String oauthUsername = authenticatorProperties.get(
                    IproovAuthenticatorConstants.ConfigProperties.OAUTH_USERNAME.getName());
            String oauthPassword = authenticatorProperties.get(
                    IproovAuthenticatorConstants.ConfigProperties.OAUTH_PASSWORD.getName());

            String verificationMode = request.getParameter(IproovAuthenticatorConstants.SCENARIO);
            String isValidated;
            if (IproovAuthenticatorConstants.Verification.AUTHENTICATION.equals(verificationMode)) {
                String verifyToken = (String) context.getProperty(IproovAuthenticatorConstants.VERIFY_TOKEN);
                isValidated = IproovAuthorizationAPIClient.validateVerification(baseUrl,
                        IproovAuthenticatorConstants.TokenEndpoints.IPROOV_VALIDATE_VERIFICATION_PATH, apiKey,
                        apiSecret, userId, verifyToken);
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

            if (!Boolean.parseBoolean(isValidated)) {
                handleIProovFailedAttempts(authenticatedUserFromContext);
                throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages
                        .IPROOV_VERIFICATION_TOKEN_VALIDATING_FAILURE);
            }

            //Set the authenticated user.
            context.setSubject(authenticatedUserFromContext);
            if (IproovAuthenticatorConstants.Verification.ENROLLMENT.equals(verificationMode)) {
                UserStoreManager userStoreManager = getUserStoreManager(authenticatedUserFromContext);
                Map<String, String> claims = new HashMap<>();
                claims.put(IproovAuthenticatorConstants.IPROOV_ENROLLED_CLAIM, "true");
                userStoreManager.setUserClaimValues(username, claims, null);

            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Successfully logged in the user " + userId);
            }
        } catch (UserStoreException e) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages
                    .RETRIEVING_USER_STORE_FAILURE, e);
        } catch (UserIdNotFoundException e) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages.USER_NOT_FOUND);
        } catch (AuthenticationFailedException e) {
            throw getIproovAuthnFailedException(IproovAuthenticatorConstants.ErrorMessages
                    .IPROOV_SETTING_IPROOV_CLAIM_VALUE_FAILURE, e);
        }
    }

    private void handleIProovFailedAttempts(AuthenticatedUser authenticatedUser) throws AuthenticationFailedException,
            UserStoreException {

        UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
        // Add required meta properties to the event.
        Map<String, Object> metaProperties = new HashMap<>();
        metaProperties.put(AUTHENTICATOR_NAME, getName());
        metaProperties.put(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM, IproovAuthenticatorConstants
                .IPROOV_FAILED_LOGIN_ATTEMPTS_CLAIM);
        metaProperties.put(USER_STORE_MANAGER, userStoreManager);
        metaProperties.put(OPERATION_STATUS, false);

        triggerEvent(authenticatedUser, metaProperties);
    }

    /**
     * Trigger event.
     *
     * @param user            Authenticated user.
     * @param eventProperties Meta details.
     * @throws AuthenticationFailedException If an error occurred while triggering the event.
     */
    protected void triggerEvent(AuthenticatedUser user,
                                Map<String, Object> eventProperties) throws AuthenticationFailedException {
        try {
            HashMap<String, Object> properties = new HashMap<>();
            properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUserName());
            properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
            properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
            if (eventProperties != null) {
                for (Map.Entry<String, Object> metaProperty : eventProperties.entrySet()) {
                    if (StringUtils.isNotBlank(metaProperty.getKey()) && metaProperty.getValue() != null) {
                        properties.put(metaProperty.getKey(), metaProperty.getValue());
                    }
                }
            }
            Event identityMgtEvent = new Event(IdentityEventConstants.Event.POST_NON_BASIC_AUTHENTICATION, properties);
            IproovAuthenticatorDataHolder.getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            throw new AuthenticationFailedException("Error occurred while handling event", e);
        }
    }

    /**
     * Get user claim value.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @return User claim value.
     * @throws AuthenticationFailedException If an error occurred while getting the claim value.
     */
    private String getClaimValue(AuthenticatedUser authenticatedUser, String claimUrl)
            throws AuthenticationFailedException, UserStoreException {

        UserStoreManager userStoreManager = getUserStoreManager(authenticatedUser);
        try {
            Map<String, String> claimValues =
                    userStoreManager.getUserClaimValues(MultitenantUtils.getTenantAwareUsername(
                            authenticatedUser.toFullQualifiedUsername()), new String[]{claimUrl}, null);
            return claimValues.get(claimUrl);
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

    private boolean isIproovProgressiveEnrollmentEnabled(AuthenticationContext context) {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String enableProgressiveEnrollment = authenticatorProperties.get(
                IproovAuthenticatorConstants.ConfigProperties.ENABLE_PROGRESSIVE_ENROLLMENT.getName());
        return Boolean.parseBoolean(enableProgressiveEnrollment);
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
