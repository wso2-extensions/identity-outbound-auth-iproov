package org.wso2.carbon.identity.application.authenticator.iproov.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.iproov.IproovAuthenticator;

/**
 * Service component for the Iproov Authenticator.
 */
@Component(
        name = "iproov.federated.authenticator",
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
            if (log.isDebugEnabled()) {
                log.debug("Iproov Authenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.fatal(" Error while activating iproov authenticator bundle ", e);
        }
    }

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

}
