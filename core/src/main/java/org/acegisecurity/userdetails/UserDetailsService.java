/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.providers.dao;

import org.springframework.dao.DataAccessException;


/**
 * Defines an interface for implementations that wish to provide data access
 * services to the {@link DaoAuthenticationProvider}.
 * 
 * <p>
 * The interface requires only one read-only method, which simplifies support
 * of new data access strategies.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface AuthenticationDao {
    //~ Methods ================================================================

    /**
     * Locates the user based on the username. The search is case insensitive,
     * meaning the implementation must return any matching object irrespective
     * of the mixture of uppercase and lowercase characters in the username.
     *
     * @param username the username presented to the {@link
     *        DaoAuthenticationProvider}
     *
     * @return a fully populated user record
     *
     * @throws UsernameNotFoundException if the user could not be found or the
     *         user has no GrantedAuthority
     * @throws DataAccessException if user could not be found for a
     *         repository-specific reason
     */
    public User loadUserByUsername(String username)
                            throws UsernameNotFoundException, 
                                   DataAccessException;
}
