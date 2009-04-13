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

import org.springframework.security.core.Authentication;
import org.springframework.ldap.core.DirContextOperations;


/**
 * The strategy interface for locating and authenticating an Ldap user.
 * <p>
 * The LdapAuthenticationProvider calls this interface to authenticate a user
 * and obtain the information for that user from the directory.
 *
 * @author Luke Taylor
 * @version $Id$
 *
 * @see org.springframework.security.ldap.populator.DefaultLdapAuthoritiesPopulator
 * @see org.springframework.security.ldap.populator.UserDetailsServiceLdapAuthoritiesPopulator
 */
public interface LdapAuthenticator {
    //~ Methods ========================================================================================================

    /**
     * Authenticates as a user and obtains additional user information from the directory.
     *
     * @param authentication
     * @return the details of the successfully authenticated user.
     */
    DirContextOperations authenticate(Authentication authentication);
}
