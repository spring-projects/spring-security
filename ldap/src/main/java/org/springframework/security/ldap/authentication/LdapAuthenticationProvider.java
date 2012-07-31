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

package org.springframework.security.ldap.authentication;

import org.springframework.ldap.NamingException;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.ppolicy.PasswordPolicyException;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.util.Assert;

import java.util.*;


/**
 * An {@link org.springframework.security.authentication.AuthenticationProvider} implementation that authenticates
 * against an LDAP server.
 * <p>
 * There are many ways in which an LDAP directory can be configured so this class delegates most of
 * its responsibilities to two separate strategy interfaces, {@link LdapAuthenticator}
 * and {@link LdapAuthoritiesPopulator}.
 *
 * <h3>LdapAuthenticator</h3>
 * This interface is responsible for performing the user authentication and retrieving
 * the user's information from the directory. Example implementations are {@link
 * org.springframework.security.ldap.authentication.BindAuthenticator BindAuthenticator} which authenticates
 * the user by "binding" as that user, and
 * {@link org.springframework.security.ldap.authentication.PasswordComparisonAuthenticator PasswordComparisonAuthenticator}
 * which compares the supplied password with the value stored in the directory, using an LDAP "compare"
 * operation.
 * <p>
 * The task of retrieving the user attributes is delegated to the authenticator because the permissions on the
 * attributes may depend on the type of authentication being used; for example, if binding as the user, it may be
 * necessary to read them with the user's own permissions (using the same context used for the bind operation).
 *
 * <h3>LdapAuthoritiesPopulator</h3>
 * Once the user has been authenticated, this interface is called to obtain the set of granted authorities for the
 * user.
 * The {@link DefaultLdapAuthoritiesPopulator DefaultLdapAuthoritiesPopulator}
 * can be configured to obtain user role information from the user's attributes and/or to perform a search for
 * "groups" that the user is a member of and map these to roles.
 *
 * <p>
 * A custom implementation could obtain the roles from a completely different source, for example from a database.
 *
 * <h3>Configuration</h3>
 *
 * A simple configuration might be as follows:
 * <pre>
 *   &lt;bean id=&quot;contextSource&quot;
 *       class=&quot;org.springframework.security.ldap.DefaultSpringSecurityContextSource&quot;&gt;
 *     &lt;constructor-arg value=&quot;ldap://monkeymachine:389/dc=springframework,dc=org&quot;/&gt;
 *     &lt;property name=&quot;userDn&quot; value=&quot;cn=manager,dc=springframework,dc=org&quot;/&gt;
 *     &lt;property name=&quot;password&quot; value=&quot;password&quot;/&gt;
 *   &lt;/bean&gt;
 *
 *   &lt;bean id=&quot;ldapAuthProvider&quot;
 *       class=&quot;org.springframework.security.ldap.authentication.LdapAuthenticationProvider&quot;&gt;
 *     &lt;constructor-arg&gt;
 *       &lt;bean class=&quot;org.springframework.security.ldap.authentication.BindAuthenticator&quot;&gt;
 *           &lt;constructor-arg ref=&quot;contextSource&quot;/&gt;
 *           &lt;property name=&quot;userDnPatterns&quot;&gt;&lt;list&gt;&lt;value&gt;uid={0},ou=people&lt;/value&gt;&lt;/list&gt;&lt;/property&gt;
 *       &lt;/bean&gt;
 *     &lt;/constructor-arg&gt;
 *     &lt;constructor-arg&gt;
 *       &lt;bean class=&quot;org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator&quot;&gt;
 *           &lt;constructor-arg ref=&quot;contextSource&quot;/&gt;
 *           &lt;constructor-arg value=&quot;ou=groups&quot;/&gt;
 *           &lt;property name=&quot;groupRoleAttribute&quot; value=&quot;ou&quot;/&gt;
 *       &lt;/bean&gt;
 *     &lt;/constructor-arg&gt;
 *   &lt;/bean&gt;
 *</pre>
 *
 * <p>
 * This would set up the provider to access an LDAP server with URL
 * <tt>ldap://monkeymachine:389/dc=springframework,dc=org</tt>. Authentication will be performed by attempting to bind
 * with the DN <tt>uid=&lt;user-login-name&gt;,ou=people,dc=springframework,dc=org</tt>. After successful
 * authentication, roles will be assigned to the user by searching under the DN
 * <tt>ou=groups,dc=springframework,dc=org</tt> with the default filter <tt>(member=&lt;user's-DN&gt;)</tt>. The role
 * name will be taken from the "ou" attribute of each match.
 * <p>
 * The authenticate method will reject empty passwords outright. LDAP servers may allow an anonymous
 * bind operation with an empty password, even if a DN is supplied. In practice this means that if
 * the LDAP directory is configured to allow unauthenticated access, it might be possible to
 * authenticate as <i>any</i> user just by supplying an empty password.
 * More information on the misuse of unauthenticated access can be found in
 * <a href="http://www.ietf.org/internet-drafts/draft-ietf-ldapbis-authmeth-19.txt">
 * draft-ietf-ldapbis-authmeth-19.txt</a>.
 *
 *
 * @author Luke Taylor
 *
 * @see BindAuthenticator
 * @see DefaultLdapAuthoritiesPopulator
 */
public class LdapAuthenticationProvider extends AbstractLdapAuthenticationProvider {
    //~ Instance fields ================================================================================================

    private LdapAuthenticator authenticator;
    private LdapAuthoritiesPopulator authoritiesPopulator;
    private boolean hideUserNotFoundExceptions = true;

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
        this.setAuthoritiesPopulator(new NullLdapAuthoritiesPopulator());
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

    public void setHideUserNotFoundExceptions(boolean hideUserNotFoundExceptions) {
        this.hideUserNotFoundExceptions = hideUserNotFoundExceptions;
    }

    @Override
    protected DirContextOperations doAuthentication(UsernamePasswordAuthenticationToken authentication) {
        try {
            return getAuthenticator().authenticate(authentication);
        } catch (PasswordPolicyException ppe) {
            // The only reason a ppolicy exception can occur during a bind is that the account is locked.
            throw new LockedException(messages.getMessage(ppe.getStatus().getErrorCode(),
                    ppe.getStatus().getDefaultMessage()));
        } catch (UsernameNotFoundException notFound) {
            if (hideUserNotFoundExceptions) {
                throw new BadCredentialsException(messages.getMessage(
                        "LdapAuthenticationProvider.badCredentials", "Bad credentials"));
            } else {
                throw notFound;
            }
        } catch (NamingException ldapAccessFailure) {
            throw new InternalAuthenticationServiceException(ldapAccessFailure.getMessage(), ldapAccessFailure);
        }
    }

    @Override
    protected Collection<? extends GrantedAuthority> loadUserAuthorities(DirContextOperations userData, String username, String password) {
        return getAuthoritiesPopulator().getGrantedAuthorities(userData, username);
    }

}

