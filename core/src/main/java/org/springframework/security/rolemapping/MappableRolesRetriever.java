package org.springframework.security.rolemapping;

/**
 * Interface to be implemented by classes that can retrieve a list of mappable
 * roles (for example the list of all available J2EE roles in a web or EJB
 * application).
 *
 * @author Ruud Senden
 * @since 2.0
 */
public interface MappableRolesRetriever {
    /**
     * Implementations of this method should return a list of all mappable
     * roles.
     *
     * @return list of all mappable roles
     */
    String[] getMappableRoles();
}
