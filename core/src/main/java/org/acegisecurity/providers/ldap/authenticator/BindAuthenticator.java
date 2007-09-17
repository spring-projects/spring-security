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

import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.Authentication;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.ldap.SpringSecurityLdapTemplate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.util.Assert;

import javax.naming.directory.DirContext;
import java.util.Iterator;


/**
 * An authenticator which binds as a user.
 *
 * @author Luke Taylor
 * @version $Id$
 *
 * @see AbstractLdapAuthenticator
 */
public class BindAuthenticator extends AbstractLdapAuthenticator {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(BindAuthenticator.class);

    //~ Constructors ===================================================================================================

    /**
     * Create an initialized instance to the {@link InitialDirContextFactory} provided.
     *
     * @param initialDirContextFactory
     */
    public BindAuthenticator(InitialDirContextFactory initialDirContextFactory) {
        super(initialDirContextFactory);
    }

    //~ Methods ========================================================================================================

    public DirContextOperations authenticate(Authentication authentication) {
        DirContextOperations user = null;
        Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication,
                "Can only process UsernamePasswordAuthenticationToken objects");

        String username = authentication.getName();
        String password = (String)authentication.getCredentials();

        // If DN patterns are configured, try authenticating with them directly
        Iterator dns = getUserDns(username).iterator();

        while (dns.hasNext() && user == null) {
            user = bindWithDn((String) dns.next(), username, password);
        }

        // Otherwise use the configured locator to find the user
        // and authenticate with the returned DN.
        if (user == null && getUserSearch() != null) {
            DirContextOperations userFromSearch = getUserSearch().searchForUser(username);
            user = bindWithDn(userFromSearch.getDn().toString(), username, password);
        }

        if (user == null) {
            throw new BadCredentialsException(
                    messages.getMessage("BindAuthenticator.badCredentials", "Bad credentials"));
        }

        return user;
    }

    private DirContextOperations bindWithDn(String userDn, String username, String password) {
        SpringSecurityLdapTemplate template = new SpringSecurityLdapTemplate(
                new BindWithSpecificDnContextSource(getInitialDirContextFactory(), userDn, password));

        try {
            return template.retrieveEntry(userDn, getUserAttributes());

        } catch (BadCredentialsException e) {
            // This will be thrown if an invalid user name is used and the method may
            // be called multiple times to try different names, so we trap the exception
            // unless a subclass wishes to implement more specialized behaviour.
            handleBindException(userDn, username, e.getCause());
        }

        return null;
    }

    /**
     * Allows subclasses to inspect the exception thrown by an attempt to bind with a particular DN.
     * The default implementation just reports the failure to the debug log.
     */
    void handleBindException(String userDn, String username, Throwable cause) {
        if (logger.isDebugEnabled()) {
            logger.debug("Failed to bind as " + userDn + ": " + cause);
        }
    }

    private class BindWithSpecificDnContextSource implements ContextSource {
        private InitialDirContextFactory ctxFactory;
        private String userDn;
        private String password;

        public BindWithSpecificDnContextSource(InitialDirContextFactory ctxFactory, String userDn, String password) {
            this.ctxFactory = ctxFactory;
            this.userDn = userDn;
            this.password = password;
        }

        public DirContext getReadOnlyContext() throws DataAccessException {
            return ctxFactory.newInitialDirContext(userDn, password);
        }

        public DirContext getReadWriteContext() throws DataAccessException {
            return getReadOnlyContext();
        }
    }

}
