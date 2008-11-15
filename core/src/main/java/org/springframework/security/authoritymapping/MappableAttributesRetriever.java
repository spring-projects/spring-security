package org.springframework.security.authoritymapping;

import java.util.Set;

/**
 * Interface to be implemented by classes that can retrieve a list of mappable
 * security attribute strings (for example the list of all available J2EE roles in a web or EJB
 * application).
 *
 * @author Ruud Senden
 * @since 2.0
 */
public interface MappableAttributesRetriever {
    /**
     * Implementations of this method should return a set of all string attributes which
     * can be mapped to <tt>GrantedAuthority</tt>s.
     *
     * @return set of all mappable roles
     */
    Set<String> getMappableAttributes();
}
