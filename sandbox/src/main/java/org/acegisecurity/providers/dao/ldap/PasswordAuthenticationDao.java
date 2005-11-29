/* Copyright 2004 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.acegisecurity.providers.dao.ldap;

import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.userdetails.UserDetails;

import org.springframework.dao.DataAccessException;


/**
 * Defines an interface for DAO implementations capable of locating and also
 * validating a password.
 * 
 * <p>
 * Used with the {@link PasswordDaoAuthenticationProvider}.
 * </p>
 * 
 * <p>
 * The interface requires only one read-only method, which simplifies support
 * of new data access strategies.
 * </p>
 * 
 * @deprecated instead subclass {@link org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider}
 * @author Karel Miarka
 */
public interface PasswordAuthenticationDao {
    //~ Methods ================================================================

    /**
     * Locates the user based on the username and password. In the actual
     * implementation, the search may possibly be case sensitive, or case
     * insensitive depending on how the implementaion instance is configured.
     * In this case, the <code>UserDetails</code> object that comes back may
     * have a username that is of a different case than what was actually
     * requested.
     * 
     * <p>
     * The implementation is responsible for password validation. It must throw
     * <code>BadCredentialsException</code> (or subclass of that exception if
     * desired) if the provided password is invalid.
     * </p>
     * 
     * <p>
     * The implementation is responsible for filling the username and password
     * parameters into the implementation of <code>UserDetails</code>.
     * </p>
     *
     * @param username the username presented to the {@link
     *        PasswordDaoAuthenticationProvider}
     * @param password the password presented to the {@link
     *        PasswordDaoAuthenticationProvider}
     *
     * @return a fully populated user record
     *
     * @throws DataAccessException if user could not be found for a
     *         repository-specific reason
     * @throws BadCredentialsException if the user could not be found, invalid
     *         password provided or the user has no
     *         <code>GrantedAuthority</code>s
     */
    public UserDetails loadUserByUsernameAndPassword(String username,
        String password) throws DataAccessException, BadCredentialsException;
}
