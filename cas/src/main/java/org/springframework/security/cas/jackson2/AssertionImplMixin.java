package org.springframework.security.cas.jackson2;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.jasig.cas.client.authentication.AttributePrincipal;

import java.util.Date;
import java.util.Map;

/**
 * @author Jitendra Singh
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonIgnoreProperties(value = {"valid"})
public class AssertionImplMixin {

    @JsonCreator
    public AssertionImplMixin(@JsonProperty("principal") AttributePrincipal principal,
                              @JsonProperty("validFromDate") Date validFromDate, @JsonProperty("validUntilDate") Date validUntilDate,
                              @JsonProperty("authenticationDate") Date authenticationDate, @JsonProperty("attributes") Map<String, Object> attributes){

    }
}
