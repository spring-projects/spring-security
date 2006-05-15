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

import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.ldap.LdapTemplate;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.userdetails.ldap.LdapUserDetails;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;

import java.util.Iterator;

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


    //~ Constructors ===========================================================

    public BindAuthenticator(InitialDirContextFactory initialDirContextFactory) {
        super(initialDirContextFactory);
    }

    //~ Methods ================================================================

    public LdapUserDetails authenticate(String username, String password) {

        LdapUserDetails user = null;

        // If DN patterns are configured, try authenticating with them directly
        Iterator dns = getUserDns(username).iterator();

        while(dns.hasNext() && user == null) {
            user = bindWithDn((String)dns.next(), password);
        }

        // Otherwise use the configured locator to find the user
        // and authenticate with the returned DN.
        if (user == null && getUserSearch() != null) {
            LdapUserDetails userFromSearch = getUserSearch().searchForUser(username);
            user = bindWithDn(userFromSearch.getDn(), password);
        }

        if(user == null) {
            throw new BadCredentialsException(messages.getMessage(
                            "BindAuthenticator.badCredentials",
                            "Bad credentials"));
        }

        return user;

    }

    LdapUserDetails bindWithDn(String userDn, String password) {
        LdapTemplate template = new LdapTemplate(getInitialDirContextFactory(), userDn, password);

        if (logger.isDebugEnabled()) {
            logger.debug("Attempting to bind with DN = " + userDn);
        }

        try {

            Object user = (LdapUserDetails)template.retrieveEntry(userDn, getUserDetailsMapper(), getUserAttributes());
            Assert.isInstanceOf(LdapUserDetails.class, user, "Entry mapper must return an LdapUserDetails instance");

            return (LdapUserDetails) user;

        } catch(BadCredentialsException e) {
            // This will be thrown if an invalid user name is used and the method may
            // be called multiple times to try different names, so we trap the exception.
            if (logger.isDebugEnabled()) {
                logger.debug("Failed to bind as " + userDn + ": " + e.getCause());
            }
        }

        return null;
    }
}
