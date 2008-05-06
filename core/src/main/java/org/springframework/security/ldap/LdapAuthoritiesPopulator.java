/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.ldap;

import org.springframework.security.GrantedAuthority;

import org.springframework.ldap.core.DirContextOperations;


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
    //~ Methods ========================================================================================================

    /**
     * Get the list of authorities for the user.
     *
     * @param userData the context object which was returned by the LDAP authenticator.
     *
     * @return the granted authorities for the given user.
     *
     */
    GrantedAuthority[] getGrantedAuthorities(DirContextOperations userData, String username);
}
