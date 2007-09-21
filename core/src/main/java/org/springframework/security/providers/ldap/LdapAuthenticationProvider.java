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

package org.springframework.security.providers.ldap;

import org.springframework.security.AuthenticationException;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.AuthenticationServiceException;

import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.providers.ldap.authenticator.LdapShaPasswordEncoder;
import org.springframework.security.providers.encoding.PasswordEncoder;
import org.springframework.security.providers.dao.AbstractUserDetailsAuthenticationProvider;

import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.ldap.UserDetailsContextMapper;
import org.springframework.security.userdetails.ldap.LdapUserDetailsMapper;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.dao.DataAccessException;
import org.springframework.ldap.core.DirContextOperations;


/**
 * An {@link org.springframework.security.providers.AuthenticationProvider} implementation that provides integration with an
 * LDAP server.
 *
 * <p>There are many ways in which an LDAP directory can be configured so this class delegates most of
 * its responsibilites to two separate strategy interfaces, {@link LdapAuthenticator}
 * and {@link LdapAuthoritiesPopulator}.</p>
 *
 * <h3>LdapAuthenticator</h3>
 * This interface is responsible for performing the user authentication and retrieving
 * the user's information from the directory. Example implementations are {@link
 * org.springframework.security.providers.ldap.authenticator.BindAuthenticator BindAuthenticator} which authenticates the user by
 * "binding" as that user, and {@link org.springframework.security.providers.ldap.authenticator.PasswordComparisonAuthenticator
 * PasswordComparisonAuthenticator} which performs a comparison of the supplied password with the value stored in the
 * directory, either by retrieving the password or performing an LDAP "compare" operation.
 * <p>The task of retrieving the user attributes is delegated to the authenticator because the permissions on the
 * attributes may depend on the type of authentication being used; for example, if binding as the user, it may be
 * necessary to read them with the user's own permissions (using the same context used for the bind operation).</p>
 *
 * <h3>LdapAuthoritiesPopulator</h3>
 * Once the user has been authenticated, this interface is called to obtain the set of granted authorities for the
 * user.
 * The
 * {@link org.springframework.security.providers.ldap.populator.DefaultLdapAuthoritiesPopulator DefaultLdapAuthoritiesPopulator}
 * can be configured to obtain user role information from the user's attributes and/or to perform a search for
 * "groups" that the user is a member of and map these to roles.
 *
 * <p>A custom implementation could obtain the roles from a completely different source, for example from a database.
 * </p>
 *
 * <h3>Configuration</h3>
 *
 * A simple configuration might be as follows:
 * <pre>
 *    &lt;bean id="initialDirContextFactory" class="org.springframework.security.providers.ldap.DefaultInitialDirContextFactory">
 *      &lt;constructor-arg value="ldap://monkeymachine:389/dc=acegisecurity,dc=org"/>
 *      &lt;property name="managerDn">&lt;value>cn=manager,dc=acegisecurity,dc=org&lt;/value>&lt;/property>
 *      &lt;property name="managerPassword">&lt;value>password&lt;/value>&lt;/property>
 *    &lt;/bean>
 *
 *    &lt;bean id="ldapAuthProvider" class="org.springframework.security.providers.ldap.LdapAuthenticationProvider">
 *      &lt;constructor-arg>
 *        &lt;bean class="org.springframework.security.providers.ldap.authenticator.BindAuthenticator">
 *          &lt;constructor-arg>&lt;ref local="initialDirContextFactory"/>&lt;/constructor-arg>
 *          &lt;property name="userDnPatterns">&lt;list>&lt;value>uid={0},ou=people&lt;/value>&lt;/list>&lt;/property>
 *        &lt;/bean>
 *      &lt;/constructor-arg>
 *      &lt;constructor-arg>
 *        &lt;bean class="org.springframework.security.providers.ldap.populator.DefaultLdapAuthoritiesPopulator">
 *          &lt;constructor-arg>&lt;ref local="initialDirContextFactory"/>&lt;/constructor-arg>
 *          &lt;constructor-arg>&lt;value>ou=groups&lt;/value>&lt;/constructor-arg>
 *          &lt;property name="groupRoleAttribute">&lt;value>ou&lt;/value>&lt;/property>
 *        &lt;/bean>
 *      &lt;/constructor-arg>
 *    &lt;/bean></pre>
 *
 * <p>This would set up the provider to access an LDAP server with URL
 * <tt>ldap://monkeymachine:389/dc=acegisecurity,dc=org</tt>. Authentication will be performed by attempting to bind
 * with the DN <tt>uid=&lt;user-login-name&gt;,ou=people,dc=acegisecurity,dc=org</tt>. After successful
 * authentication, roles will be assigned to the user by searching under the DN
 * <tt>ou=groups,dc=acegisecurity,dc=org</tt> with the default filter <tt>(member=&lt;user's-DN&gt;)</tt>. The role
 * name will be taken from the "ou" attribute of each match.</p>
 * <p>
 * The authenticate method will reject empty passwords outright. LDAP servers may allow an anonymous
 * bind operation with an empty password, even if a DN is supplied. In practice this means that if
 * the LDAP directory is configured to allow unauthenitcated access, it might be possible to
 * authenticate as <i>any</i> user just by supplying an empty password.
 * More information on the misuse of unauthenticated access can be found in
 * <a href="http://www.ietf.org/internet-drafts/draft-ietf-ldapbis-authmeth-19.txt">
 * draft-ietf-ldapbis-authmeth-19.txt</a>.
 * </p>
 *
 * @author Luke Taylor
 * @version $Id$
 *
 * @see org.springframework.security.providers.ldap.authenticator.BindAuthenticator
 * @see org.springframework.security.providers.ldap.populator.DefaultLdapAuthoritiesPopulator
 */
public class LdapAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(LdapAuthenticationProvider.class);

    //~ Instance fields ================================================================================================

    private LdapAuthenticator authenticator;
    private LdapAuthoritiesPopulator authoritiesPopulator;
    private UserDetailsContextMapper userDetailsContextMapper = new LdapUserDetailsMapper();
    private PasswordEncoder passwordEncoder = new LdapShaPasswordEncoder();
    private boolean includeDetailsObject = true;

    //~ Constructors ===================================================================================================

    /**
     * Create an instance with the supplied authenticator and authorities populator implementations.
     *
     * @param authenticator the authentication strategy (bind, password comparison, etc)
     *          to be used by this provider for authenticating users.
     * @param authoritiesPopulator the strategy for obtaining the authorities for a given user after they've been
     *          authenticated.
     */
    public LdapAuthenticationProvider(LdapAuthenticator authenticator, LdapAuthoritiesPopulator authoritiesPopulator) {
        this.setAuthenticator(authenticator);
        this.setAuthoritiesPopulator(authoritiesPopulator);
    }

    /**
     * Creates an instance with the supplied authenticator and a null authorities populator.
     * In this case, the authorities must be mapped from the user context.
     *
     * @param authenticator the authenticator strategy.
     */
    public LdapAuthenticationProvider(LdapAuthenticator authenticator) {
        this.setAuthenticator(authenticator);
        this.setAuthoritiesPopulator(new NullAuthoritiesPopulator());
    }

    //~ Methods ========================================================================================================

    private void setAuthenticator(LdapAuthenticator authenticator) {
        Assert.notNull(authenticator, "An LdapAuthenticator must be supplied");
        this.authenticator = authenticator;
    }

    private LdapAuthenticator getAuthenticator() {
        return authenticator;
    }

    private void setAuthoritiesPopulator(LdapAuthoritiesPopulator authoritiesPopulator) {
        Assert.notNull(authoritiesPopulator, "An LdapAuthoritiesPopulator must be supplied");
        this.authoritiesPopulator = authoritiesPopulator;
    }

    protected LdapAuthoritiesPopulator getAuthoritiesPopulator() {
        return authoritiesPopulator;
    }

    public void setUserDetailsContextMapper(UserDetailsContextMapper userDetailsContextMapper) {
        Assert.notNull(userDetailsContextMapper, "UserDetailsContextMapper must not be null");
        this.userDetailsContextMapper = userDetailsContextMapper;
    }

    protected UserDetailsContextMapper getUserDetailsContextMapper() {
        return userDetailsContextMapper;
    }

    protected void additionalAuthenticationChecks(UserDetails userDetails,
                                                  UsernamePasswordAuthenticationToken authentication)
        throws AuthenticationException {
		String presentedPassword = authentication.getCredentials() == null ? "" :
                authentication.getCredentials().toString();
        if (!passwordEncoder.isPasswordValid(userDetails.getPassword(), presentedPassword, null)) {
            throw new BadCredentialsException(messages.getMessage(
                    "AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"),
                    includeDetailsObject ? userDetails : null);
        }
    }

    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        if (!StringUtils.hasLength(username)) {
            throw new BadCredentialsException(messages.getMessage("LdapAuthenticationProvider.emptyUsername",
                    "Empty Username"));
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Retrieving user " + username);
        }

        String password = (String) authentication.getCredentials();
        Assert.notNull(password, "Null password was supplied in authentication token");

        if (password.length() == 0) {
            logger.debug("Rejecting empty password for user " + username);
            throw new BadCredentialsException(messages.getMessage("LdapAuthenticationProvider.emptyPassword",
                    "Empty Password"));
        }

        try {
            DirContextOperations user = getAuthenticator().authenticate(authentication);

            GrantedAuthority[] extraAuthorities = getAuthoritiesPopulator().getGrantedAuthorities(user, username);

            return userDetailsContextMapper.mapUserFromContext(user, username, extraAuthorities);

        } catch (DataAccessException ldapAccessFailure) {
            throw new AuthenticationServiceException(ldapAccessFailure.getMessage(), ldapAccessFailure);
        }
    }

    public boolean isIncludeDetailsObject() {
        return includeDetailsObject;
    }

    public void setIncludeDetailsObject(boolean includeDetailsObject) {
        this.includeDetailsObject = includeDetailsObject;
    }

    //~ Inner Classes ==================================================================================================

    private static class NullAuthoritiesPopulator implements LdapAuthoritiesPopulator {
        public GrantedAuthority[] getGrantedAuthorities(DirContextOperations userDetails, String username) {
            return new GrantedAuthority[0];
        }
    }
}

