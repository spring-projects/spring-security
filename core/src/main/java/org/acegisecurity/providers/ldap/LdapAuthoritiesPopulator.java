/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package org.acegisecurity.providers.ldap;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.ldap.LdapDataAccessException;

import javax.naming.directory.Attributes;

/**
 * Obtains a list of granted authorities for an Ldap user.
 * <p>
 * Used by the <tt>LdapAuthenticationProvider</tt> once a user has been
 * authenticated to create the final user details object.
 * </p>
 *
 * @author Luke Taylor
 * @version $Id$
 */
public interface LdapAuthoritiesPopulator {

    /**
     * Get the list of authorities for the user.
     *
     * @param username the login name which was passed to the LDAP provider.
     * @param userDn the full DN of the user
     * @param userAttributes the user's LDAP attributes that were retrieved from the directory.
     * @return the granted authorities for the given user.
     * @throws org.acegisecurity.ldap.LdapDataAccessException if there is a problem accessing the directory.
     */
    GrantedAuthority[] getGrantedAuthorities(String username, String userDn, Attributes userAttributes)
            throws LdapDataAccessException;

}
