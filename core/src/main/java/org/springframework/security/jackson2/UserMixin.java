package org.springframework.security.jackson2;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * @author Jitendra Singh
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonDeserialize(using = UserDeserializer.class)
public abstract class UserMixin {

    public UserMixin(@JsonProperty("username") String username, @JsonProperty("password") String password,
                     @JsonProperty("enabled") boolean enabled, @JsonProperty("accountNonExpired") boolean accountNonExpired,
                     @JsonProperty("credentialsNonExpired") boolean credentialsNonExpired,
                     @JsonProperty("accountNonLocked") boolean accountNonLocked, @JsonProperty("authorities") Collection<? extends GrantedAuthority> authorities) {
    }
}
