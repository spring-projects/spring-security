package org.acegisecurity.userdetails;

/**
 * An extension of the {@link UserDetailsService} which provides the ability
 * to create new users and update existing ones.
 *
 * @author Luke
 * @version $Id$
 */
public interface UserDetailsManager extends UserDetailsService {

    /**
     * Save details for the supplied user, or update
     *
     * @param user
     */
    void createUser(UserDetails user);

    void updateUser(UserDetails user);

    void deleteUser(String username);

    boolean userExists(String username);

}
