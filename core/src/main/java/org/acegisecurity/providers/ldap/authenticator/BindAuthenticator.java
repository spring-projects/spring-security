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

package org.acegisecurity.providers.ldap.authenticator;

import org.acegisecurity.providers.ldap.*;
import org.acegisecurity.BadCredentialsException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.naming.directory.DirContext;
import javax.naming.directory.Attributes;
import javax.naming.NamingException;

/**
 * An authenticator which binds as a user.
 *
 * @see AbstractLdapAuthenticator
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class BindAuthenticator extends AbstractLdapAuthenticator {

    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(BindAuthenticator.class);

    //~ Methods ================================================================

    public LdapUserDetails authenticate(String username, String password) {

        String dn = getUserDn(username);
        LdapUserDetails user = null;

        // If DN is pattern is configured, try authenticating with that directly
        if(dn != null) {
            user = authenticateWithDn(dn, password);
        }

        // Otherwise use the configured locator to find the user
        // and authenticate with the returned DN.
        if(user == null && getUserSearch() != null) {
            LdapUserDetails userFromSearch = getUserSearch().searchForUser(username);
            user = authenticateWithDn(userFromSearch.getDn(), password);
        }

        if(user == null) {
            throw new BadCredentialsException("Failed to authenticate as " + username);
        }

        return user;

    }

    private LdapUserDetails authenticateWithDn(String userDn, String password) {
        DirContext ctx = null;
        LdapUserDetails user = null;
        Attributes attributes = null;

        if(logger.isDebugEnabled()) {
            logger.debug("Binding with DN = " + userDn);
        }

        try {
            ctx = getInitialDirContextFactory().newInitialDirContext(userDn, password);
            attributes = ctx.getAttributes(
                    LdapUtils.getRelativeName(userDn, ctx),
                    getUserAttributes());
            user = new LdapUserDetails(userDn, attributes);
            
        } catch(NamingException ne) {
            throw new LdapDataAccessException("Failed to load attributes for user " + userDn, ne);
        } catch(BadCredentialsException e) {
            // This will be thrown if an invalid user name is used and the method may
            // be called multiple times to try different names, so we trap the exception.            
            logger.debug("Failed to bind as " + userDn + ", " + e.getMessage());
        } finally {
            LdapUtils.closeContext(ctx);
        }

        return user;
    }

}
