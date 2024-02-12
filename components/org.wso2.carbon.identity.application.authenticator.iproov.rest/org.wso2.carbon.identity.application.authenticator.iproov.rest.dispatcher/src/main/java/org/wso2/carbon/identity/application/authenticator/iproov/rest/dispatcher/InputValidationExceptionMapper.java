package org.wso2.carbon.identity.application.authenticator.iproov.rest.dispatcher;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authenticator.iproov.rest.common.error.ErrorDTO;
import org.wso2.carbon.identity.application.authenticator.iproov.rest.common.error.ErrorResponse;

import java.util.Set;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

import static org.wso2.carbon.identity.application.authenticator.iproov.rest.dispatcher.ErrorConstants.ERROR_CODE;
import static org.wso2.carbon.identity.application.authenticator.iproov.rest.dispatcher.ErrorConstants.ERROR_DESCRIPTION;
import static org.wso2.carbon.identity.application.authenticator.iproov.rest.dispatcher.ErrorConstants.ERROR_MESSAGE;

/**
 * An exception mapper class that maps input validation exceptions.
 */
public class InputValidationExceptionMapper implements ExceptionMapper<ConstraintViolationException> {

    private static final Log LOG = LogFactory.getLog(InputValidationExceptionMapper.class);

    @Override
    public Response toResponse(ConstraintViolationException e) {

        StringBuilder description = new StringBuilder();
        Set<ConstraintViolation<?>> constraintViolations = e.getConstraintViolations();

        for (ConstraintViolation constraintViolation : constraintViolations) {
            if (StringUtils.isNotBlank(description)) {
                description.append(" ");
            }
            description.append(constraintViolation.getMessage());
        }

        if (StringUtils.isBlank(description)) {
            description = new StringBuilder(ERROR_DESCRIPTION);
        }

        ErrorDTO errorDTO = new ErrorResponse.Builder()
                .withCode(ERROR_CODE)
                .withMessage(ERROR_MESSAGE)
                .withDescription(description.toString())
                .build(LOG, e.getMessage(), true);

        return Response.status(Response.Status.BAD_REQUEST)
                .entity(errorDTO)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON).build();
    }
}
