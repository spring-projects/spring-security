package org.springframework.security.web.jackson2;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

/**
 * @author Jitendra Singh
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
public class WebAuthenticationDetailsMixin {

    @JsonCreator
    WebAuthenticationDetailsMixin(@JsonProperty("remoteAddress") String remoteAddress,
                                  @JsonProperty("sessionId") String sessionId) {
    }
}
