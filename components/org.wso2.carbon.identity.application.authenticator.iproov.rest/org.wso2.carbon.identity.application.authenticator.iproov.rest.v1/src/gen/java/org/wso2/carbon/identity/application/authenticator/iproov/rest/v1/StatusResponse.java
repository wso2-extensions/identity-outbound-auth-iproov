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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.time.OffsetDateTime;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;
import javax.validation.Valid;
import javax.xml.bind.annotation.*;

public class StatusResponse  {
  
    private String sessionKey;
    private OffsetDateTime timeStamp;

@XmlType(name="StatusEnum")
@XmlEnum(String.class)
public enum StatusEnum {

    @XmlEnumValue("REQUEST_SENT") REQUEST_SENT(String.valueOf("REQUEST_SENT")), @XmlEnumValue("INITIATED") INITIATED(String.valueOf("INITIATED")), @XmlEnumValue("INITIATED_RESPONSE") INITIATED_RESPONSE(String.valueOf("INITIATED_RESPONSE")), @XmlEnumValue("COMPLETED") COMPLETED(String.valueOf("COMPLETED")), @XmlEnumValue("CANCELED") CANCELED(String.valueOf("CANCELED")), @XmlEnumValue("FAILED") FAILED(String.valueOf("FAILED"));


    private String value;

    StatusEnum(String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    @Override
    public String toString() {
        return String.valueOf(value);
    }

    public static StatusEnum fromValue(String value) {
        for (StatusEnum b : StatusEnum.values()) {
            if (b.value.equals(value)) {
                return b;
            }
        }
        throw new IllegalArgumentException("Unexpected value '" + value + "'");
    }
}

    private StatusEnum status;

    /**
    **/
    public StatusResponse sessionKey(String sessionKey) {

        this.sessionKey = sessionKey;
        return this;
    }
    
    @ApiModelProperty(example = "bf98f2b5caca07c703d2401f4298967d9829ded2978dffc04c4b95cf61f87a49", value = "")
    @JsonProperty("sessionKey")
    @Valid
    public String getSessionKey() {
        return sessionKey;
    }
    public void setSessionKey(String sessionKey) {
        this.sessionKey = sessionKey;
    }

    /**
    **/
    public StatusResponse timeStamp(OffsetDateTime timeStamp) {

        this.timeStamp = timeStamp;
        return this;
    }
    
    @ApiModelProperty(value = "")
    @JsonProperty("timeStamp")
    @Valid
    public OffsetDateTime getTimeStamp() {
        return timeStamp;
    }
    public void setTimeStamp(OffsetDateTime timeStamp) {
        this.timeStamp = timeStamp;
    }

    /**
    **/
    public StatusResponse status(StatusEnum status) {

        this.status = status;
        return this;
    }
    
    @ApiModelProperty(example = "COMPLETED", value = "")
    @JsonProperty("status")
    @Valid
    public StatusEnum getStatus() {
        return status;
    }
    public void setStatus(StatusEnum status) {
        this.status = status;
    }



    @Override
    public boolean equals(java.lang.Object o) {

        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        StatusResponse statusResponse = (StatusResponse) o;
        return Objects.equals(this.sessionKey, statusResponse.sessionKey) &&
            Objects.equals(this.timeStamp, statusResponse.timeStamp) &&
            Objects.equals(this.status, statusResponse.status);
    }

    @Override
    public int hashCode() {
        return Objects.hash(sessionKey, timeStamp, status);
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append("class StatusResponse {\n");
        
        sb.append("    sessionKey: ").append(toIndentedString(sessionKey)).append("\n");
        sb.append("    timeStamp: ").append(toIndentedString(timeStamp)).append("\n");
        sb.append("    status: ").append(toIndentedString(status)).append("\n");
        sb.append("}");
        return sb.toString();
    }

    /**
    * Convert the given object to string with each line indented by 4 spaces
    * (except the first line).
    */
    private String toIndentedString(java.lang.Object o) {

        if (o == null) {
            return "null";
        }
        return o.toString().replace("\n", "\n");
    }
}

