package org.springframework.security.core.authority.mapping;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;

/**
 * Interface to be implemented by classes that can map a list of security attributes (such as roles or
 * group names) to a collection of Spring Security {@code GrantedAuthority}s.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public interface Attributes2GrantedAuthoritiesMapper {
    /**
     * Implementations of this method should map the given collection of attributes to a
     * collection of Spring Security GrantedAuthorities. There are no restrictions for the
     * mapping process; a single attribute can be mapped to multiple Spring Security
     * GrantedAuthorities, all attributes can be mapped to a single Spring Security
     * {@code GrantedAuthority}, some attributes may not be mapped, etc.
     *
     * @param attributes the attributes to be mapped
     * @return the collection of authorities created from the attributes
     */
    public Collection<? extends GrantedAuthority> getGrantedAuthorities(Collection<String> attributes);
}
