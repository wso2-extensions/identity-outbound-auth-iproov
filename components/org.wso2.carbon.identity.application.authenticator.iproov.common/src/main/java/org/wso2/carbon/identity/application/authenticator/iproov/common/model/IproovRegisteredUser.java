package org.wso2.carbon.identity.application.authenticator.iproov.common.model;

/**
 * Model class for the request which obtain the iProov registered user by the given username.
 */
public class IproovRegisteredUser {

    private String userId;
    private String userName;
    private String status;
    private String activationDate;

    public String getUserId() {

        return userId;
    }

    public void setUserId(final String userId) {

        this.userId = userId;
    }

    public String getUserName() {

        return userName;
    }

    public void setUserName(final String userName) {

        this.userName = userName;
    }

    public String getStatus() {

        return status;
    }

    public void setStatus(final String status) {

        this.status = status;
    }

    public String getActivationDate() {

        return activationDate;
    }

    public void setActivationDate(final String activationDate) {

        this.activationDate = activationDate;
    }

    public IproovRegisteredUser(IproovRegisteredUser iproovRegisteredUser) {

        this.userId = iproovRegisteredUser.getUserId();
        this.userName = iproovRegisteredUser.getUserName();
        this.status = iproovRegisteredUser.getStatus();
        this.activationDate = iproovRegisteredUser.getActivationDate();
    }
}
