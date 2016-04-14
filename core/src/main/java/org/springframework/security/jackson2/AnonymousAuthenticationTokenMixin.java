package org.springframework.security.jackson2;

import com.fasterxml.jackson.annotation.*;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * @author Jitendra Singh
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class AnonymousAuthenticationTokenMixin {

    @JsonCreator
    public AnonymousAuthenticationTokenMixin(@JsonProperty("keyHash") Integer keyHash, @JsonProperty("principal") Object principal,
                                             @JsonProperty("authorities") Collection<? extends GrantedAuthority> authorities) {
    }
}
