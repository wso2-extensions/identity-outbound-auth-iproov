/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.iproov.rest.v1;

import org.springframework.beans.factory.annotation.Autowired;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.Multipart;
import java.io.InputStream;
import java.util.List;

import org.wso2.carbon.identity.application.authenticator.iproov.rest.v1.Error;
import org.wso2.carbon.identity.application.authenticator.iproov.rest.v1.StatusResponse;
import org.wso2.carbon.identity.application.authenticator.iproov.rest.v1.AuthenticationApiService;

import javax.validation.Valid;
import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import io.swagger.annotations.*;

import javax.validation.constraints.*;

@Path("/authentication")
@Api(description = "The authentication API")

public class AuthenticationApi  {

    @Autowired
    private AuthenticationApiService delegate;

    @Valid
    @GET
    @Path("/status/{sessionKey}")
    
    @Produces({ "application/json" })
    @ApiOperation(value = "Retrieve user authentication status.", notes = "This API is used to retrieve a user's authentication status when logging in via iProov.", response = StatusResponse.class, tags={ "iProov Authentication" })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "OK", response = StatusResponse.class),
        @ApiResponse(code = 400, message = "Invalid input in the request.", response = Error.class),
        @ApiResponse(code = 500, message = "Internal server error.", response = Error.class)
    })
    public Response getAuthenticationStatus(@ApiParam(value = "sessionKey provided by the iProov Authenticator during the authentication initiation.",required=true) @PathParam("sessionKey") String sessionKey) {

        return delegate.getAuthenticationStatus(sessionKey );
    }

}
