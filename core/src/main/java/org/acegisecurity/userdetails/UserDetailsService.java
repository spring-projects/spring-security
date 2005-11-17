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

package org.acegisecurity.providers.dao;

import org.acegisecurity.UserDetails;

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
     * Locates the user based on the username. In the actual implementation,
     * the search may possibly be case insensitive, or case insensitive
     * depending on how the implementaion instance is configured. In this
     * case, the <code>UserDetails</code> object that comes back may have a
     * username that is of a different case than what was actually requested..
     *
     * @param username the username presented to the {@link
     *        DaoAuthenticationProvider}
     *
     * @return a fully populated user record (never <code>null</code>)
     *
     * @throws UsernameNotFoundException if the user could not be found or the
     *         user has no GrantedAuthority
     * @throws DataAccessException if user could not be found for a
     *         repository-specific reason
     */
    public UserDetails loadUserByUsername(String username)
        throws UsernameNotFoundException, DataAccessException;
}
