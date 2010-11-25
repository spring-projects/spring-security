package org.springframework.security.core.authority.mapping;

import org.springframework.security.core.GrantedAuthority;

import java.util.*;

/**
 * Mapping interface which can be injected into the authentication layer to convert the
 * authorities loaded from storage into those which will be used in the {@code Authentication} object.
 *
 * @author Luke Taylor
 */
public interface GrantedAuthoritiesMapper {
    Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities);
}
