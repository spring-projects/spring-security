package org.springframework.security.web.jackson2;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

/**
 * @author Jitendra Singh
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonDeserialize(using = CookieDeserializer.class)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, isGetterVisibility = JsonAutoDetect.Visibility.NONE)
public abstract class CookieMixin {

    @JsonCreator
    public CookieMixin(@JsonProperty("name") String name, @JsonProperty("value") String value) {
    }
}
