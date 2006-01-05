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
 * An {@link org.acegisecurity.providers.AuthenticationProvider} implementation that
 * provides integration with an LDAP server. 
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
 * <h3>Configuration</h3>
 * A simple configuration might be as follows:
 * <pre>
 *    &lt;bean id="initialDirContextFactory" class="org.acegisecurity.providers.ldap.DefaultInitialDirContextFactory">
 *      &lt;constructor-arg value="ldap://monkeymachine:389/dc=acegisecurity,dc=org"/>
 *      &lt;property name="managerDn">&lt;value>cn=manager,dc=acegisecurity,dc=org&lt;/value>&lt;/property>
 *      &lt;property name="managerPassword">&lt;value>password&lt;/value>&lt;/property>
 *    &lt;/bean>
 *
 *    &lt;bean id="ldapAuthProvider" class="org.acegisecurity.providers.ldap.LdapAuthenticationProvider">
 *    &lt;constructor-arg>
 *      &lt;bean class="org.acegisecurity.providers.ldap.authenticator.BindAuthenticator">
 *         &lt;constructor-arg>&lt;ref local="initialDirContextFactory"/>&lt;/constructor-arg>
 *         &lt;property name="userDnPatterns">&lt;list>&lt;value>uid={0},ou=people&lt;/value>&lt;/list>&lt;/property>
 *      &lt;/bean>
 *    &lt;/constructor-arg>
 *    &lt;constructor-arg>
 *      &lt;bean class="org.acegisecurity.providers.ldap.populator.DefaultLdapAuthoritiesPopulator">
 *         &lt;constructor-arg>&lt;ref local="initialDirContextFactory"/>&lt;/constructor-arg>
 *         &lt;constructor-arg>&lt;value>ou=groups&lt;/value>&lt;/constructor-arg>
 *         &lt;property name="groupRoleAttribute">&lt;value>ou&lt;/value>&lt;/property>
 *      &lt;/bean>
 *    &lt;/constructor-arg>
 *  &lt;/bean>
 * </pre>
 * <p>
 * This would set up the provider to access an LDAP server with URL
 * <tt>ldap://monkeymachine:389/dc=acegisecurity,dc=org</tt>. Authentication will be performed by
 * attempting to bind with the DN <tt>uid=&lt;user-login-name&gt;,ou=people,dc=acegisecurity,dc=org</tt>.
 * After successful authentication, roles will be assigned to the user by searching under the DN
 * <tt>ou=groups,dc=acegisecurity,dc=org</tt> with the default filter <tt>(member=&lt;user's-DN&gt;)</tt>.
 * The role name will be taken from the "ou" attribute of each match.
 * </p>
 *
 * @see org.acegisecurity.providers.ldap.authenticator.BindAuthenticator
 * @see org.acegisecurity.providers.ldap.populator.DefaultLdapAuthoritiesPopulator
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
        if (logger.isDebugEnabled()) {
            logger.debug("Retrieving user " + username);
        }

        String password = (String)authentication.getCredentials();
        Assert.hasLength(password, "Null or empty password was supplied in authentication token");

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

