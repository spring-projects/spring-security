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

import org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.*;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.User;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;

import javax.naming.directory.Attributes;

/**
 * The class responsible for LDAP authentication.
 *
 * <p>
 * There are many ways in which an LDAP directory can be configured so this class
 * delegates most of its responsibilites to two separate strategy interfaces,
 * {@link LdapAuthenticator} and {@link LdapAuthoritiesPopulator}.
 * </p>
 *
 * <h3>LdapAuthenticator</h3>
 *
 * This interface is responsible for performing the user authentication and retrieving
 * the user's information from the directory. Example implementations are
 * {@link org.acegisecurity.providers.ldap.authenticator.BindAuthenticator BindAuthenticator}
 * which authenticates the user by "binding" as that user, and
 * {@link org.acegisecurity.providers.ldap.authenticator.PasswordComparisonAuthenticator PasswordComparisonAuthenticator}
 * which performs a comparison of the supplied password with the value stored in the directory,
 * either by retrieving the password or performing an LDAP "compare" operation.
 * <p>
 * The task of retrieving the user attributes is delegated to the authenticator
 * because the permissions on the attributes may depend on the type of authentication
 * being used; for example, if binding as the user, it may be necessary to read them
 * with the user's own permissions (using the same context used for the bind operation).
 * </p>
 *
 * <h3>LdapAuthoritiesPopulator</h3>
 *
 * Once the user has been authenticated, this interface is called to obtain the set of
 * granted authorities for the user. The
 * {@link org.acegisecurity.providers.ldap.populator.DefaultLdapAuthoritiesPopulator DefaultLdapAuthoritiesPopulator}
 * can be configured to obtain user role information from the user's attributes and/or to perform
 * a search for "groups" that the user is a member of and map these to roles.
 * <p>
 * A custom implementation could obtain the roles from a completely different source,
 * for example from a database.
 * </p>
 *
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class LdapAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {
    //~ Static fields/initializers =============================================

    private static final Log logger = LogFactory.getLog(LdapAuthenticationProvider.class);

    //~ Instance fields ========================================================

    private LdapAuthenticator authenticator;

    private LdapAuthoritiesPopulator authoritiesPopulator;


    //~ Constructors ===========================================================

    public LdapAuthenticationProvider(LdapAuthenticator authenticator,
                                      LdapAuthoritiesPopulator authoritiesPopulator) {
        Assert.notNull(authenticator, "An LdapAuthenticator must be supplied");
        Assert.notNull(authoritiesPopulator, "An LdapAuthoritiesPopulator must be supplied");

        this.authenticator = authenticator;
        this.authoritiesPopulator = authoritiesPopulator;

        // TODO: Check that the role attributes specified for the populator will be retrieved
        // by the authenticator. If not, add them to the authenticator's list and log a
        // warning.

    }

    //~ Methods ================================================================

    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
    }

    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        logger.debug("Retrieving user " + username);

        String password = (String)authentication.getCredentials();
        Assert.notNull(password, "Null password was supplied in authentication token");

        LdapUserInfo ldapUser = authenticator.authenticate(username, password);

        return createUserDetails(username, password, ldapUser.getDn(), ldapUser.getAttributes());
    }

    /**
     * Creates the user final <tt>UserDetails</tt> object that will be returned by the provider
     * once the user has been authenticated.
     * <p>
     * The <tt>LdapAuthoritiesPopulator</tt> will be used to create the granted authorites for the
     * user.
     * </p>
     * <p>
     * Can be overridden to customize the mapping of user attributes to additional user information.
     * </p>
     *
     * @param username The user login, as passed to the provider
     * @param password The submitted password
     * @param userDn The DN of the user in the Ldap system.
     * @param attributes The user attributes retrieved from the Ldap system.
     * @return The UserDetails for the successfully authenticated user.
     */
    protected UserDetails createUserDetails(String username, String password, String userDn, Attributes attributes) {

        return new User(username, password, true, true, true, true,
                authoritiesPopulator.getGrantedAuthorities(username, userDn, attributes));

    }
}

