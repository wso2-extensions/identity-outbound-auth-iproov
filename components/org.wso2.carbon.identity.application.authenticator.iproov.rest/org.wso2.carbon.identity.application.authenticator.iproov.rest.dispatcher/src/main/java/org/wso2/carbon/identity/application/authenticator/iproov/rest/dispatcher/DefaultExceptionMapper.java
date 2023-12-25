package org.wso2.carbon.identity.application.authenticator.iproov.rest.dispatcher;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.iproov.rest.common.error.ErrorDTO;
import org.wso2.carbon.identity.application.authenticator.iproov.rest.common.error.ErrorResponse;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

import static org.wso2.carbon.identity.application.authenticator.iproov.rest.dispatcher.ErrorConstants.ERROR_CODE;

/**
 * An exception mapper class that handles all the unhandled server errors, (ex:NullPointer).
 * Sends a default error response.
 */
public class DefaultExceptionMapper implements ExceptionMapper<Throwable> {

    public static final String PROCESSING_ERROR_CODE = ERROR_CODE;
    public static final String PROCESSING_ERROR_MESSAGE = "Unexpected Processing Error.";
    public static final String PROCESSING_ERROR_DESCRIPTION = "Server encountered an error while serving the request.";
    private static final Log LOG = LogFactory.getLog(DefaultExceptionMapper.class);

    @Override
    public Response toResponse(Throwable e) {

        LOG.error("Server encountered an error while serving the request.", e);
        ErrorDTO errorDTO = new ErrorResponse.Builder().withCode(PROCESSING_ERROR_CODE)
                .withMessage(PROCESSING_ERROR_MESSAGE)
                .withDescription(PROCESSING_ERROR_DESCRIPTION).build();
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(errorDTO)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON).build();
    }
}
