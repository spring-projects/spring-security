package org.springframework.security.jackson2;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * @author Jitendra Singh
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class RememberMeAuthenticationTokenMixin {

    @JsonCreator
    public RememberMeAuthenticationTokenMixin(@JsonProperty("keyHash") Integer keyHash,
                                              @JsonProperty("principal") Object principal,
                                              @JsonProperty("authorities") Collection<? extends GrantedAuthority> authorities) {
    }
}
