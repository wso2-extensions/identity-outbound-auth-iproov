package org.wso2.carbon.identity.application.authenticator.iproov.connector;

import org.wso2.carbon.identity.application.authenticator.iproov.common.constants.IproovAuthenticatorConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class IProovAuthenticatorConfigImpl implements IdentityConnectorConfig {
    @Override
    public String getName() {

        return IproovAuthenticatorConstants.AUTHENTICATOR_NAME_VALUE;
    }

    @Override
    public String getFriendlyName() {

        return IproovAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME_VALUE;
    }

    @Override
    public String getCategory() {

        return "Multi Factor Authenticators";
    }

    @Override
    public String getSubCategory() {

        return "DEFAULT";
    }

    @Override
    public int getOrder() {

        return 0;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {

        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(IproovAuthenticatorConstants.ConnectorConfig.ENABLE_IPROOV_PROGRESSIVE_ENROLLMENT,
                "Enable iProov progressive enrollment");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(IproovAuthenticatorConstants.ConnectorConfig.ENABLE_IPROOV_PROGRESSIVE_ENROLLMENT,
                "Allow users to enroll with iProov progressively during the login flow");
        return descriptionMapping;
    }

    @Override
    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(IproovAuthenticatorConstants.ConnectorConfig.ENABLE_IPROOV_PROGRESSIVE_ENROLLMENT);
        return properties.toArray(new String[0]);
    }

    @Override
    public Properties getDefaultPropertyValues(String tenantDomain) {

        String enableIproovProgressiveEnrollment = "false";
        String enableIproovProgressiveEnrollmentProperty = IdentityUtil.getProperty(
                IproovAuthenticatorConstants.ConnectorConfig.ENABLE_IPROOV_PROGRESSIVE_ENROLLMENT);

        if (enableIproovProgressiveEnrollmentProperty != null) {
            enableIproovProgressiveEnrollment = enableIproovProgressiveEnrollmentProperty;
        }
        Map<String, String> defaultProperties = new HashMap<>();
        defaultProperties.put(IproovAuthenticatorConstants.ConnectorConfig.ENABLE_IPROOV_PROGRESSIVE_ENROLLMENT,
                enableIproovProgressiveEnrollment);

        Properties properties = new Properties();
        properties.putAll(defaultProperties);
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] strings, String s) {

        return null;
    }
}
