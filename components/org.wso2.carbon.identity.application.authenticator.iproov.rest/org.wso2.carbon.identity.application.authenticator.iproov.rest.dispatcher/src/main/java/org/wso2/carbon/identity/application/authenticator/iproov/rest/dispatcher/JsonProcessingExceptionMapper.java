package org.wso2.carbon.identity.application.authenticator.iproov.rest.dispatcher;


import com.fasterxml.jackson.core.JsonProcessingException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.iproov.rest.common.error.ErrorDTO;
import org.wso2.carbon.identity.application.authenticator.iproov.rest.common.error.ErrorResponse;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

import static org.wso2.carbon.identity.application.authenticator.iproov.rest.dispatcher.ErrorConstants.ERROR_CODE;
import static org.wso2.carbon.identity.application.authenticator.iproov.rest.dispatcher.ErrorConstants.ERROR_DESCRIPTION;
import static org.wso2.carbon.identity.application.authenticator.iproov.rest.dispatcher.ErrorConstants.ERROR_MESSAGE;

/**
 * AN exception mapper class that handles exceptions when an incorrect json requests body is received.
 * Sends a default error response.
 */
public class JsonProcessingExceptionMapper implements ExceptionMapper<JsonProcessingException> {

    private static final Log LOG = LogFactory.getLog(JsonProcessingExceptionMapper.class);

    @Override
    public Response toResponse(JsonProcessingException e) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Provided JSON request content is not in the valid format:", e);
        }
        ErrorDTO errorDTO = new ErrorResponse.Builder().withCode(ERROR_CODE)
                .withMessage(ERROR_MESSAGE)
                .withDescription(ERROR_DESCRIPTION).build();
        return Response.status(Response.Status.BAD_REQUEST)
                .entity(errorDTO)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON).build();
    }
}
