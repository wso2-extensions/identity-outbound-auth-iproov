<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.AuthContextAPIClient" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.Constants" %>
<%@ page import="org.wso2.carbon.identity.core.util.IdentityCoreConstants" %>
<%@ page import="org.wso2.carbon.identity.core.util.IdentityUtil" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.endpoint.util.EndpointConfigManager" %>
<%@ page import="static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.STATUS" %>
<%@ page import="static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.STATUS_MSG" %>
<%@ page import="static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.CONFIGURATION_ERROR" %>
<%@ page import="static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.AUTHENTICATION_MECHANISM_NOT_CONFIGURED" %>
<%@ page import="static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.ENABLE_AUTHENTICATION_WITH_REST_API" %>
<%@ page import="static org.wso2.carbon.identity.application.authentication.endpoint.util.Constants.ERROR_WHILE_BUILDING_THE_ACCOUNT_RECOVERY_ENDPOINT_URL" %>
<%@ page import="java.nio.charset.Charset" %>
<%@ page import="org.apache.commons.codec.binary.Base64" %>
<%@ page import="java.io.File" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.Arrays" %>
<%@ page import="java.util.Map" %>
<%@ page import="org.owasp.encoder.Encode" %>

<%@ include file="includes/localize.jsp" %>
<jsp:directive.include file="includes/init-url.jsp"/>

<!doctype html>
<html>

<head>
    <script language="JavaScript" type="text/javascript" src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
    <script language="JavaScript" type="text/javascript"
    src="https://cdn.jsdelivr.net/npm/bootstrap@4.4.1/dist/js/bootstrap.min.js"></script>

    <!-- header -->
    <%
        File headerFile = new File(getServletContext().getRealPath("extensions/header.jsp"));
        if (headerFile.exists()) {
    %>
        <jsp:include page="extensions/header.jsp"/>
    <% } else { %>
        <jsp:include page="includes/header.jsp"/>
    <% } %>

</head>

<body class="login-portal layout authentication-portal-layout">
    <main class="center-segment">
        <div class="ui container medium center aligned middle aligned" >

            <!-- product-title -->
            <%
            File productTitleFile = new File(getServletContext().getRealPath("extensions/product-title.jsp"));
            if (productTitleFile.exists()) {
            %>
                <jsp:include page="extensions/product-title.jsp"/>
            <% } else { %>
                <jsp:include page="includes/product-title.jsp"/>
            <% } %>
            <div class="ui segment">

            <h3 class="ui header">
                Login with iProov
            </h3>

             <div class="ui visible negative message" style="display: none;" id="error-msg"></div>

            <!-- Login form -->
            <form id="loginForm" action="<%=commonauthURL%>" method="POST">
                <div class="field">
                    <div class="ui fluid left icon input">
                        <input type="text" id="username"  name="username" tabindex="1" placeholder="Username" required="">
                        <i aria-hidden="true" class="user icon"></i>
                    </div>
                </div><br>
                <input id="sessionDataKeyLoginForm" type="hidden" name="sessionDataKey"
                value='<%=Encode.forHtmlAttribute(request.getParameter("sessionDataKey"))%>' />
                <div class="column mobile center aligned tablet right aligned computer right aligned buttons tablet no-margin-right-last-child computer no-margin-right-last-child">
                    <button type="button" class="ui primary large button" tabindex="4" role="button"
                     onClick="loginFormOnSubmit();">
                        Login
                    </button>
                </div>
            </form>

            <!-- Authentication on progress -->

            <div id="inProgressDisplay" >
                <h5 id="authenticationStatusMessage"></h5>
            </div>

            <!-- Proceed Authentication form -->
            <form id="completeAuthenticationForm" action="<%=commonauthURL%>" method="POST">
                <input id="sessionDataKeyAuthenticationForm" type="hidden" name="sessionDataKey"
                value='<%=Encode.forHtmlAttribute(request.getParameter("sessionDataKey"))%>' />
            </form>
        </div>
    </div>
    </main>

    <!-- product-footer -->
    <%
        File productFooterFile = new File(getServletContext().getRealPath("extensions/product-footer.jsp"));
        if (productFooterFile.exists()) {
    %>
        <jsp:include page="extensions/product-footer.jsp"/>
    <% } else { %>
        <jsp:include page="includes/product-footer.jsp"/>
    <% } %>

    <!-- footer -->
    <%
        File footerFile = new File(getServletContext().getRealPath("extensions/footer.jsp"));
        if (footerFile.exists()) {
    %>
        <jsp:include page="extensions/footer.jsp"/>
    <% } else { %>
        <jsp:include page="includes/footer.jsp"/>
    <% } %>

    <script type="text/javascript">

        var i = 0;
        var sessionDataKey;
        const refreshInterval = 5000;
        const timeout = 90000;
        var intervalListener;
        var isPollingStopped = false;
        const authStatusCheckApiWithQueryParams = "/api/iproov/v1/authentication/status/";
        const GET = 'GET';

        $(document).ready(function () {

            const urlParams = new URLSearchParams(window.location.search);
            sessionDataKey = urlParams.get('sessionDataKey');
            tenantDomain = urlParams.get('tenantDomain');

            if (urlParams.has("status")){
                const status = urlParams.get("status");

                if(status == "PENDING") {
                    document.getElementById("loginForm").style.display = 'none';
                    document.getElementById("inProgressDisplay").style.display = 'block';
                    document.getElementById("authenticationStatusMessage").innerText = "Push notification has been sent to your smartphone. Please check your smartphone.";
                    pollAuthStatus();

                } else if (status == 'CANCELED' || status == 'FAILED' || status == 'INVALID_REQUEST' || status == 'INVALID_TOKEN'){
                    handleError(urlParams.get("message"));
                }
            }
        });


        function loginFormOnSubmit() {

            const username = document.getElementById("username").value;

            if(username != ''){
                console.log("Initiate authentication request");
                initiateAuthentication();
            } else {
                handleError("Username is required.");
            }
        }

        function pollAuthStatus() {

            var startTime = new Date().getTime();
            console.log("Start time: "+ startTime);

            intervalListener = window.setInterval(function () {
                if (isPollingStopped) {
                    return;
                } else {
                    checkWaitStatus();
                    i++;
                    console.log("Polled times " + i)
                }
            }, refreshInterval);

            function checkWaitStatus() {
                const now = new Date().getTime();
                if ((startTime + timeout) < now) {
                    handleAuthenticationTimedOut();
                } else {
                    $.ajax("/t/"+ tenantDomain + authStatusCheckApiWithQueryParams + sessionDataKey, {
                    method: GET,
                    success: function (res) {
                        handleStatusResponse(res);
                    },
                    error: function (err) {
                        handleAuthenticationFailed();
                    },
                    failure: function () {
                        isPollingStopped = true;
                        window.clearInterval(intervalListener);
                    }
                });
                }

            }

            function handleStatusResponse(res) {

                if (["COMPLETED", "CANCELED", "FAILED"].includes(res.status)) {
                    completeAuthentication();
                }
            }

           function handleAuthenticationTimedOut () {
            if (!isPollingStopped) {
                const error_message = "Authentication failed due to timeout.Please try again later.";
                window.clearInterval(intervalListener);
                handleError(error_message);
            }
           }

           function handleAuthenticationFailed () {
            if (!isPollingStopped) {
                isPollingStopped = true;
                const error_message = "Authentication failed. Please try again later.";
                window.clearInterval(intervalListener);
                handleError(error_message);
            }
           }

        }

        function handleError(msg){
            const error_message = document.getElementById("error-msg");
            document.getElementById("loginForm").style.display = 'block';
            document.getElementById("inProgressDisplay").style.display = 'none';
            error_message.innerHTML = msg;
            error_message.style.display = "block";
        }

        function initiateAuthentication() {
            document.getElementById("error-msg").style.display = 'none';
            document.getElementById("loginForm").style.display = 'none';
            document.getElementById("inProgressDisplay").style.display = 'block';
            document.getElementById("authenticationStatusMessage").innerText = "Authention in progress. Please wait...";
            document.getElementById("loginForm").submit();
        }

        function completeAuthentication() {
            if (!isPollingStopped) {
                isPollingStopped = true;
                console.log("Complete authentication request");
                window.clearInterval(intervalListener);
                document.getElementById("completeAuthenticationForm").submit();
            }
        }
 </script>

</body>
</html>
