package org.wso2.carbon.identity.application.authenticator.iproov.internal;

import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Data holder for the Iproov Authenticator.
 */
public class IproovAuthenticatorDataHolder {
    private static RealmService realmService;
    private static IdentityEventService identityEventService;
    private static IdentityGovernanceService identityGovernanceService;
    private static AccountLockService accountLockService;

    private IproovAuthenticatorDataHolder() {

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

        IproovAuthenticatorDataHolder.realmService = realmService;
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

        IproovAuthenticatorDataHolder.identityEventService = identityEventService;
    }

    /**
     * Get Account Lock service.
     *
     * @return Account Lock service.
     */
    public static AccountLockService getAccountLockService() {

        return accountLockService;
    }

    /**
     * Set Account Lock service.
     *
     * @param accountLockService Account Lock service.
     */
    public static void setAccountLockService(AccountLockService accountLockService) {

        IproovAuthenticatorDataHolder.accountLockService = accountLockService;
    }
}
