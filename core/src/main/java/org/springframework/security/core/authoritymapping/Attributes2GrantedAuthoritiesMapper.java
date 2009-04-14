package org.springframework.security.core.authoritymapping;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;

/**
 * Interface to be implemented by classes that can map a list of security attributes (such as roles or
 * group names) to a list of Spring Security GrantedAuthorities.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public interface Attributes2GrantedAuthoritiesMapper {
    /**
     * Implementations of this method should map the given list of attributes to a
     * list of Spring Security GrantedAuthorities. There are no restrictions for the
     * mapping process; a single attribute can be mapped to multiple Spring Security
     * GrantedAuthorities, all attributes can be mapped to a single Spring Security
     * GrantedAuthority, some attributes may not be mapped, etc.
     *
     * @param attribute the attributes to be mapped
     * @return the list of mapped GrantedAuthorities
     */
    public List<GrantedAuthority> getGrantedAuthorities(Collection<String> attributes);
}
