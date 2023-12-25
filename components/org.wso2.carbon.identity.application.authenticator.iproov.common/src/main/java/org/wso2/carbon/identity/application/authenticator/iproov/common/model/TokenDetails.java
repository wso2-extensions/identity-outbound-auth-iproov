package org.wso2.carbon.identity.application.authenticator.iproov.common.model;

/**
 *
 */
public class TokenDetails {

    private String accessToken;
    private String tokenType;
    private int expiresIn;
    private String[] scope;

    public String getAccessToken() {
        return accessToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public int getExpiresIn() {
        return expiresIn;
    }

    public String[] getScope() {
        return scope;
    }
}
