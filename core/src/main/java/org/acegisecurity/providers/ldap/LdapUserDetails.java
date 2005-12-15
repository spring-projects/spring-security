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

import org.acegisecurity.userdetails.User;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;

import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.NamingException;

/**
 * A user representation which is used internally by the Ldap provider.
 *
 * It contains the user's distinguished name and a set of attributes that
 * have been retrieved from the Ldap server.
 * <p>
 * An instance may be created as the result of a search, or when user information
 * is retrieved during authentication.
 * </p>
 * <p>
 * An instance of this class will be used by the <tt>LdapAuthenticationProvider</tt>
 * to construct the final user details object that it returns.
 * </p>
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapUserDetails {

    //~ Instance fields ========================================================

    private String dn;
    private Attributes attributes;

    //~ Constructors ===========================================================

    /**
     *
     * @param dn the full DN of the user
     * @param attributes any attributes loaded from the user's directory entry.
     */
    public LdapUserDetails(String dn, Attributes attributes) {
        this.dn = dn;
        this.attributes = attributes;
    }

    //~ Methods ================================================================

    public String getDn() {
        return dn;
    }

    public String getRelativeName(DirContext ctx) throws NamingException {
        return LdapUtils.getRelativeName(dn, ctx);
    }

    public Attributes getAttributes() {
        return (Attributes)attributes.clone();
    }
}
