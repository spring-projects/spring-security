package org.springframework.security.cas.jackson2;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.jasig.cas.client.validation.Assertion;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

/**
 * @author Jitendra Singh
 */
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY)
@JsonIgnoreProperties(ignoreUnknown = true)
public class CasAuthenticationTokenMixin {

    @JsonCreator
    public CasAuthenticationTokenMixin(@JsonProperty("keyHash") Integer keyHash, @JsonProperty("principal") Object principal,
                                       @JsonProperty("credentials") Object credentials,
                                       @JsonProperty("authorities") Collection<? extends GrantedAuthority> authorities,
                                       @JsonProperty("userDetails") UserDetails userDetails, @JsonProperty("assertion") Assertion assertion) {

    }
}
