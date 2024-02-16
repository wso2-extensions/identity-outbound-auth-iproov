# Configuring iProov Authenticator
To use the iProov authenticator with WSO2 Identity Server, first you need to configure  the authenticator with
WSO2 Identity Server. See the instructions given below on how to configure iProov authenticator with
WSO2 Identity Server using a sample app.

To test this approach, the organization must have a service provider created in iProov portal should obtain
the relevant keys and secrets of the created service provider.

After deploying the iProov authenticator on WSO2 IS, the authenticator can be configured from the
WSO2 IS Console.

## Prerequisites
To use the connector, you'll need:

- A configured iProov service provider.

Note: Get the support from iProov to configure a iProov service provider via the iProov Portal.

## Setting up and installing the iProov connector

**Step 1:** Extracting the project artifacts
1. Clone the `identity-outbound-auth-iproov` repository.
2. Build the project by running ```mvn clean install``` in the root directory.

Note : The latest project artifacts can also be downloaded from the Connector Store.

**Step 2:** Deploying the iProov Authenticator

1. Navigate to `identity-outbound-auth-iproov/components` → `org.wso2.carbon.identity.application.authenticator.iproov`
   → `target`.
2. Copy the `org.wso2.carbon.identity.application.authenticator.iproov-1.0.0-SNAPSHOT.jar` file.
3. Navigate to `<IS_HOME>/repository/components/dropins`.
4. Paste the `.jar` file into the dropins directory.
5. Alternatively, it's possible to drag and drop the `.jar` file to the dropins directory.
6. Next, navigate to `identity-outbound-auth-iproov/components` →
   `org.wso2.carbon.identity.application.authenticator.iproov.common` → `target`.
7. Copy the `org.wso2.carbon.identity.application.authenticator.iproov.common-1.0.0-SNAPSHOT.jar` file.
8. Navigate to `<IS_HOME>/repository/components/lib` directory and paste the `.jar` file.
9. Navigate to `identity-outbound-auth-iproov/components` → `org.wso2.carbon.identity.application.authenticator.iproov`
   → `src/main/resources/artifacts` and copy the `iproov` directory.
10. Paste it into `<IS_HOME>/repository/resources/identity/extensions/connections` directory.
11. Navigate to `identity-outbound-auth-iproov/components` → `org.wso2.carbon.identity.application.authenticator.iproov`
   → `src/main/resources/artifacts` and copy the `guides` directory.
12. Paste it into `<IS_HOME>/repository/deployment/server/webapps/console/resources/connections/assets/images` directory.

**Step 3:** Deploying the iproov login page
1. Copy `iproovlogin.jsp` in the downloaded artifacts.
2. Navigate to `<IS_HOME>/repository/deployment/server/webapps` → `authenticationendpoint`.
3. Paste or drop the `JSP` file in the `authenticationendpoint` directory.
4. Add the following configurations to `Resources.properties` file in the 
`<IS_HOME>/repository/deployment/server/webapps/authenticationendpoint/WEB-INF/classes/org/wso2/carbon/identity/application/authentication/endpoint/i18n` directory. Please note
the following messages can be customized as per the preference.
    ```
    # iProov
    iproov.heading=Login with your bio-metric authenticator
    iproov.login.button=Login
    iproov.scan.face.button=Scan Face with iProov
    iproov.rescan.face.button=Rescan Face with iProov
    iproov.authentication.failed.message=Authentication Failed. Try again.
    iproov.grant.camera.access.message=Grant camera access to use your bio-metric authenticator.
    iproov.grant.camera.access.button=Grant Permission
    iproov.username.error=Username is required.
    iproov.timeout.error=Authentication failed due to timeout. Please try again later.
    iproov.generic.error=Authentication failed. Please try again later.
    iproov.auth.start=Authentication in progress. Please wait...
    ```
   
5. Add the following configuration to `deployment.toml` file in the `<IS_HOME>/repository/conf` directory.
    ```
   [authentication.endpoint.redirect_params]
   filter_policy = "exclude"
   remove_on_consume_from_api = "false"
   parameters = ["loggedInUser", "ske", "verifyToken", "enrollToken"]
   
    ```
   
6. Restart the WSO2 Identity Server.


**Step 4:** Adding required identity claims to the product
1.execute the following curl commands to add the required identity claims to the product.
```
    curl --location '<server-url>/t/<tenant-domain>/api/server/v1/claim-dialects/local/claims' \
    --header 'accept: application/json' \
    --header 'authorization: Basic <Base 64 encoded username:password>' \
    --header 'Content-Type: application/json' \
    --data '{
    "claimURI": "http://wso2.org/claims/identity/iproovEnrolled",
    "description": "Whether user is being enrolled with iProov",
    "displayOrder": 0,
    "displayName": "iProov enrolled",
    "readOnly": true,
    "regEx": "",
    "required": false,
    "supportedByDefault": false,
    "attributeMapping": [
    {
    "mappedAttribute": "iproovEnrolled",
    "userstore": "PRIMARY"
    }
    ]
    }'
```
```
    curl --location '<server-url>/t/<tenant-domain>/api/server/v1/claim-dialects/local/claims' \
    --header 'accept: application/json' \
    --header 'authorization: Basic  <Base 64 encoded username:password>' \
    --header 'Content-Type: application/json' \
    --data '{
    "claimURI": "http://wso2.org/claims/identity/failediProovAttempts",
    "description": "Failed iProov Attempts.",
    "displayOrder": 0,
    "displayName": "Failed iProov Attempts",
    "readOnly": true,
    "regEx": "",
    "required": false,
    "supportedByDefault": false,
    "attributeMapping": [
    {
    "mappedAttribute": "failediProovAttempts",
    "userstore": "PRIMARY"
    }
    ]
    }'
```

## The WSO2 console's UI for the iproov authenticator

The WSO2 Console's UI for the iproov connector enables developers to easily configure iproov
as an identity provider for their application. The UI offers a user-friendly and intuitive
interface for defining essential iproov credentials, such as base URL, oauth username, oauth password,
api key and api secret
![Configuring iProov in WSO2 Console](images/wso2console.png)

### Base URL
This refers to the Base URL you received from iProov upon creating a service provider for your organization.
Example :

```
https://eu.rp.secure.iproov.me/api/v2
```

### Oauth username
This refers to the oauth username you received for the service provider you created in the iProov.
Example :
```
admin
```

### OAuth password
This refers to the oauth password you received for the service provider you created in the iProov.
Example :
```
*************************************51f
```

### API Key
This refers to the api key you received for the service provider you created in the iProov.
Example :
```
*************************************652
```

### API Secret
This refers to the secret key you received for the service provider you created in the iProov.
Example :
```
*************************************d19
```
