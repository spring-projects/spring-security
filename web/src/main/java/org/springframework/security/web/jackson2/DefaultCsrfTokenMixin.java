package org.springframework.security.web.jackson2;

import com.fasterxml.jackson.annotation.*;

/**
 * Mix-in class for {@link org.springframework.security.web.csrf.DefaultCsrfToken} to enable Jackson
 * serialization support.
 *
 * @author Jitendra Singh
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public class DefaultCsrfTokenMixin {

    /**
     * JsonCreator constructor needed by Jackson to create {@link org.springframework.security.web.csrf.DefaultCsrfToken}
     * object.
     *
     * @param headerName
     * @param parameterName
     * @param token
     */
    @JsonCreator
    public DefaultCsrfTokenMixin(@JsonProperty("headerName") String headerName,
                                 @JsonProperty("parameterName") String parameterName, @JsonProperty("token") String token) {
    }
}
