package org.wso2.carbon.identity.application.authenticator.iproov.rest.common.error;


import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

/**
 * Common Exception class for all the API related errors.
 */
public class APIError extends WebApplicationException {

    private static final long serialVersionUID = -5096160501895108984L;
    private String message;
    private String code;
    private ErrorDTO responseEntity;
    private Response.Status status;

    /**
     * API Error Constructor with status and error response.
     *
     * @param status        Status enum of Response object.
     * @param errorResponse Error data object.
     */
    public APIError(Response.Status status, ErrorDTO errorResponse) {

        this.responseEntity = errorResponse;
        this.message = status.getReasonPhrase();
        this.code = errorResponse.getCode();
        this.status = status;
    }

    /**
     * API Error Constructor with status, message and error response.
     *
     * @param status        Status enum of Response object.
     * @param message       Error message.
     * @param errorResponse Error data object.
     */
    public APIError(Response.Status status, String message, ErrorDTO errorResponse) {

        this(status, errorResponse);
        this.message = message;
        this.code = errorResponse.getCode();
        this.status = status;
    }

    @Override
    public String getMessage() {

        return message;
    }

    public String getCode() {

        return code;
    }

    public ErrorDTO getResponseEntity() {

        return responseEntity;
    }

    public Response.Status getStatus() {

        return status;
    }
}
