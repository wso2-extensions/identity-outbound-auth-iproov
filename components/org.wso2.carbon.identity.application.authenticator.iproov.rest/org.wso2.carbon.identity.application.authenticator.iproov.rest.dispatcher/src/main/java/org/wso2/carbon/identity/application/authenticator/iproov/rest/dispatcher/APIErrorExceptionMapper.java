package org.wso2.carbon.identity.application.authenticator.iproov.rest.dispatcher;

import org.wso2.carbon.identity.application.authenticator.iproov.rest.common.error.APIError;

import java.util.ResourceBundle;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

/**
 *
 */
public class APIErrorExceptionMapper implements ExceptionMapper<WebApplicationException> {

    static final String BUNDLE = "ErrorMappings";
    static ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE);

    private static Response.Status getHttpsStatusCode(String errorCode, Response.Status defaultStatus) {

        Response.Status mappedStatus = null;
        try {
            String statusCodeValue = resourceBundle.getString(errorCode);
            mappedStatus = Response.Status.fromStatusCode(Integer.parseInt(statusCodeValue));
        } catch (Throwable ignored) {
        }
        return mappedStatus != null ? mappedStatus : defaultStatus;
    }

    @Override
    public Response toResponse(WebApplicationException e) {

        if (e instanceof APIError) {
            Object response = ((APIError) e).getResponseEntity();
            Response.Status status = getHttpsStatusCode(((APIError) e).getCode(), ((APIError) e).getStatus());
            return buildResponse(response, status);
        }
        return e.getResponse();
    }

    private Response buildResponse(Object response, Response.Status status) {

        if (response == null) {
            return Response.status(status)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON).build();
        }
        return Response.status(status)
                .entity(response)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON).build();
    }
}
