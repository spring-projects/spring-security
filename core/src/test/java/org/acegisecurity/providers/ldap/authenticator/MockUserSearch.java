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

package org.acegisecurity.providers.ldap.authenticator;

import org.acegisecurity.ldap.LdapUserSearch;

import org.acegisecurity.userdetails.ldap.LdapUserDetails;


/**
 * 
DOCUMENT ME!
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class MockUserSearch implements LdapUserSearch {
    //~ Instance fields ================================================================================================

    LdapUserDetails user;

    //~ Constructors ===================================================================================================

    public MockUserSearch(LdapUserDetails user) {
        this.user = user;
    }

    //~ Methods ========================================================================================================

    public LdapUserDetails searchForUser(String username) {
        return user;
    }
}
