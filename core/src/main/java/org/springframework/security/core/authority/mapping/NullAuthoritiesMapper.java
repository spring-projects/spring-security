package org.springframework.security.core.authority.mapping;

import org.springframework.security.core.GrantedAuthority;

import java.util.*;

/**
 * @author Luke Taylor
 */
public class NullAuthoritiesMapper implements GrantedAuthoritiesMapper {
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        return authorities;
    }
}
