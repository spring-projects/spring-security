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

package org.acegisecurity.ldap;

/**
 * Obtains a user's information from the LDAP directory given a login name.
 * <p>
 * May be optionally used to configure the LDAP authentication implementation when
 * a more sophisticated approach is required than just using a simple username->DN
 * mapping.
 * </p>
 *
 * @author Luke Taylor
 * @version $Id$
 */
public interface LdapUserSearch {

    /**
     * Locates a single user in the directory and returns the LDAP information
     * for that user.
     *
     * @param username the login name supplied to the authentication service.
     * @return an LdapUserInfo object containing the user's full DN and requested attributes.
     * TODO: Need to optionally supply required attributes here for the search.
     */
    LdapUserInfo searchForUser(String username);

}
