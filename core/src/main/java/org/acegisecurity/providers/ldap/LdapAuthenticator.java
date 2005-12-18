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

/**
 * The strategy interface for locating and authenticating an Ldap user.
 * <p>
 * The LdapAuthenticationProvider calls this interface to authenticate a user
 * and obtain the information for that user from the directory.
 * </p>
 *
 *
 * @author Luke Taylor
 * @version $Id$
 */
public interface LdapAuthenticator {
    /**
     * Authenticates as a user and obtains additional user information
     * from the directory.
     *
     * @param username the user's login name (<em>not</em> their DN).
     * @param password the user's password supplied at login.
     * @return the details of the successfully authenticated user.
     */
    LdapUserInfo authenticate(String username, String password);
}
