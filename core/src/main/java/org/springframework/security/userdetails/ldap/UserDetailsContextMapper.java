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
package org.springframework.security.userdetails.ldap;

import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.GrantedAuthority;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DirContextAdapter;

/**
 * Operations to map a UserDetails object to and from a Spring LDAP <tt>DirContextOperations</tt> implementation.
 * Used by LdapUserDetailsManager when loading and saving/creating user information.
 *
 * @author Luke Taylor
 * @since 2.0
 * @version $Id$
 */
public interface UserDetailsContextMapper {

    /**
     * Creates a fully populated UserDetails object for use by the security framework.
     *
     * @param ctx the context object which contains the user information.
     * @param username the user's supplied login name.
     * @param authority the list of authorities which the user should be given.
     * @return the user object.
     */
    UserDetails mapUserFromContext(DirContextOperations ctx, String username, GrantedAuthority[] authority);

    /**
     * Reverse of the above operation. Populates a context object from the supplied user object.
     * Called when saving a user, for example.
     */
    void mapUserToContext(UserDetails user, DirContextAdapter ctx);
}
