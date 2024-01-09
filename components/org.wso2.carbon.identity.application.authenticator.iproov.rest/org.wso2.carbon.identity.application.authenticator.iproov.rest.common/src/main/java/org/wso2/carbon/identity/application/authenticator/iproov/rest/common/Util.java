package org.wso2.carbon.identity.application.authenticator.iproov.rest.common;

import org.slf4j.MDC;
import org.wso2.carbon.identity.application.authenticator.iproov.common.constants.IproovAuthenticatorConstants;

import java.util.UUID;

/**
 * Util class for Iproov Authenticator.
 */
public class Util {
    /**
     * Get correlation id of current thread.
     *
     * @return Correlation-id.
     */
    public static String getCorrelation() {

        if (isCorrelationIDPresent()) {
            return MDC.get(IproovAuthenticatorConstants.CORRELATION_ID_KEY);
        }
        return UUID.randomUUID().toString();
    }

    /**
     * Check whether correlation id present in the log MDC.
     *
     * @return whether the correlation id is present.
     */
    public static boolean isCorrelationIDPresent() {

        return MDC.get(IproovAuthenticatorConstants.CORRELATION_ID_KEY) != null;
    }

}
