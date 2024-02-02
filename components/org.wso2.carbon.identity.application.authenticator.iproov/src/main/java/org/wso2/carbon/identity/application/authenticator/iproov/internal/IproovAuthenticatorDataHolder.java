package org.wso2.carbon.identity.application.authenticator.iproov.internal;

import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.claim.metadata.mgt.ClaimMetadataManagementService;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Data holder for the Iproov Authenticator.
 */
public class IproovAuthenticatorDataHolder {

    private static final IproovAuthenticatorDataHolder iproovAuthenticatorDataHolder =
            new IproovAuthenticatorDataHolder();

    private static RealmService realmService;
    private static IdentityEventService identityEventService;
    private static ClaimMetadataManagementService claimMetadataManagementService;
    private static IdpManager idpManager;
    private static ApplicationManagementService applicationManagementService;
    private static ConfigurationManager configurationManager;
    private static IdentityGovernanceService identityGovernanceService;

    private IproovAuthenticatorDataHolder() {

    }

    public static IproovAuthenticatorDataHolder getInstance() {

        return iproovAuthenticatorDataHolder;
    }

    /**
     * Get the RealmService.
     *
     * @return RealmService.
     */
    public static RealmService getRealmService() {

        if (realmService == null) {
            throw new RuntimeException("RealmService was not set during the iProov service component startup");
        }
        return realmService;
    }

    /**
     * Set the RealmService.
     *
     * @param realmService RealmService.
     */
    public static void setRealmService(RealmService realmService) {

        iproovAuthenticatorDataHolder.realmService = realmService;
    }

    /**
     * Get IdpManager.
     *
     * @return IdpManager.
     */
    public static IdpManager getIdpManager() {

        if (idpManager == null) {
            throw new RuntimeException("IdpManager not available. Component is not started properly.");
        }
        return idpManager;
    }

    /**
     * Set IdpManager.
     *
     * @param idpManager IdpManager.
     */
    public static void setIdpManager(IdpManager idpManager) {

        iproovAuthenticatorDataHolder.idpManager = idpManager;
    }

    /**
     * Get ApplicationManagementService instance.
     *
     * @return ApplicationManagementService instance.
     */
    public static ApplicationManagementService getApplicationManagementService() {

        if (applicationManagementService == null) {
            throw new RuntimeException(
                    "applicationManagementService not available. Component is not started properly.");
        }
        return applicationManagementService;
    }

    /**
     * Set applicationManagementService instance.
     *
     * @param applicationManagementService applicationManagementService instance.
     */
    public static void setApplicationManagementService(ApplicationManagementService applicationManagementService) {

        iproovAuthenticatorDataHolder.applicationManagementService = applicationManagementService;
    }

    /**
     * Get Identity Governance service.
     *
     * @return Identity Governance service.
     */
    public static IdentityGovernanceService getIdentityGovernanceService() {

        if (identityGovernanceService == null) {
            throw new RuntimeException("IdentityGovernanceService not available. Component is not started properly.");
        }
        return identityGovernanceService;
    }

    /**
     * Set Identity Governance service.
     *
     * @param identityGovernanceService Identity Governance service.
     */
    public static void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        IproovAuthenticatorDataHolder.identityGovernanceService = identityGovernanceService;
    }

    /**
     * Get {@link ClaimMetadataManagementService}.
     *
     * @return ClaimMetadataManagementService.
     */
    public static ClaimMetadataManagementService getClaimMetadataManagementService() {

        return iproovAuthenticatorDataHolder.claimMetadataManagementService;
    }

    /**
     * Set {@link ClaimMetadataManagementService}.
     *
     * @param claimMetadataManagementService Instance of {@link ClaimMetadataManagementService}.
     */
    public static void setClaimMetadataManagementService(ClaimMetadataManagementService
                                                                 claimMetadataManagementService) {

        iproovAuthenticatorDataHolder.claimMetadataManagementService = claimMetadataManagementService;
    }

    /**
     * Get IdentityEventService instance.
     *
     * @return IdentityEventService instance.
     */
    public static IdentityEventService getIdentityEventService() {

        return identityEventService;
    }

    /**
     * Set IdentityEventService instance.
     *
     * @param identityEventService IdentityEventService instance.
     */
    public static void setIdentityEventService(IdentityEventService identityEventService) {

        iproovAuthenticatorDataHolder.identityEventService = identityEventService;
    }

    public static void setConfigurationManager(ConfigurationManager configurationManager) {

        iproovAuthenticatorDataHolder.configurationManager = configurationManager;
    }

    public static ConfigurationManager getConfigurationManager() {

        return configurationManager;
    }
}
