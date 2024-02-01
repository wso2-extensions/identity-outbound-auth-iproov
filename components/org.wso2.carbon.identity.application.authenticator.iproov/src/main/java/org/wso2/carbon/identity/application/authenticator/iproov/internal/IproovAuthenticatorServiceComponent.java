package org.wso2.carbon.identity.application.authenticator.iproov.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.iproov.IproovAuthenticator;
import org.wso2.carbon.identity.application.authenticator.iproov.connector.IProovAuthenticatorConfigImpl;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Service component for the Iproov Authenticator.
 */
@Component(
        name = "identity.application.authenticator.iproov.component",
        immediate = true
)
public class IproovAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(IproovAuthenticatorServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            IproovAuthenticator iproovAuthenticator = new IproovAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    iproovAuthenticator, null);
            ctxt.getBundleContext().registerService(IdentityConnectorConfig.class,
                    new IProovAuthenticatorConfigImpl(), null);
            if (log.isDebugEnabled()) {
                log.debug("Iproov Authenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.fatal(" Error while activating iproov authenticator bundle ", e);
        }
    }

/*    @Activate
    protected void activate(ComponentContext ctxt) {

        IproovAuthenticator iproovAuthenticator = new IproovAuthenticator();
        IproovAuthenticatorDataHolder dataHolder = IproovAuthenticatorDataHolder.getInstance();
        BundleContext bundleContext = ctxt.getBundleContext();

        try {
            bundleContext.registerService(ApplicationAuthenticator.class.getName(),
                    iproovAuthenticator, null);
            bundleContext.registerService(IdentityConnectorConfig.class.getName(),
                    new IProovAuthenticatorConfigImpl(), null);
            if (log.isDebugEnabled()) {
                log.debug("Iproov Authenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.fatal(" Error while activating iproov authenticator bundle ", e);
        }
        dataHolder.setBundleContext(bundleContext);
    }*/


    /**
     * This method is to deactivate the HYPR authenticator the service.
     *
     * @param ctxt The Component Context
     */
    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("Iproov Authenticator bundle is deactivated");
        }
    }

    @Reference(
            name = "RealmService",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        IproovAuthenticatorDataHolder.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        IproovAuthenticatorDataHolder.setRealmService(null);
    }

    @Reference(
            name = "IdentityGovernanceService",
            service = org.wso2.carbon.identity.governance.IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService")
    protected void setIdentityGovernanceService(IdentityGovernanceService idpManager) {

        IproovAuthenticatorDataHolder.setIdentityGovernanceService(idpManager);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService idpManager) {

        IproovAuthenticatorDataHolder.setIdentityGovernanceService(null);
    }

}
