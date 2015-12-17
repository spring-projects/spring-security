/*
 * Copyright 2002-2015 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.ldap.authentication.ad;

import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.support.DefaultDirObjectFactory;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.authentication.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticationProvider;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.OperationNotSupportedException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.InitialLdapContext;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Hashtable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Abstract LDAP authentication provider which uses Active Directory configuration
 * conventions.
 * <p/>
 * The user authorities are obtained from the data contained in the {@code memberOf}
 * attribute.
 * <p/>
 * <h3>Active Directory Sub-Error Codes</h3>
 * <p/>
 * When an authentication fails, resulting in a standard LDAP 49 error code, Active
 * Directory also supplies its own sub-error codes within the error message. These will be
 * used to provide additional log information on why an authentication has failed. Typical
 * examples are
 * <p/>
 * <ul>
 * <li>525 - user not found</li>
 * <li>52e - invalid credentials</li>
 * <li>530 - not permitted to logon at this time</li>
 * <li>532 - password expired</li>
 * <li>533 - account disabled</li>
 * <li>701 - account expired</li>
 * <li>773 - user must reset password</li>
 * <li>775 - account locked</li>
 * </ul>
 * <p/>
 * If you set the {@link #setConvertSubErrorCodesToExceptions(boolean)
 * convertSubErrorCodesToExceptions} property to {@code true}, the codes will also be used
 * to control the exception raised.
 * <p/>
 * Usually, you would only need the standard implementation of {@link ActiveDirectoryLdapAuthenticationProvider}
 * but you can implement the
 * {@link #createBindPrincipal(UsernamePasswordAuthenticationToken)} and the
 * {@link #createSearchPrincipal(UsernamePasswordAuthenticationToken)}
 * methods yourself to modify the standard behaviour.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @author Dieter Hubau
 * @see ActiveDirectoryLdapAuthenticationProvider for the standard implementation
 * @since 4.1
 */
public abstract class AbstractActiveDirectoryLdapAuthenticationProvider extends AbstractLdapAuthenticationProvider {

    protected static final Pattern SUB_ERROR_CODE = Pattern.compile(".*data\\s([0-9a-f]{3,4}).*");

    // Error codes
    protected static final int USERNAME_NOT_FOUND = 0x525;
    protected static final int INVALID_PASSWORD = 0x52e;
    protected static final int NOT_PERMITTED = 0x530;
    protected static final int PASSWORD_EXPIRED = 0x532;
    protected static final int ACCOUNT_DISABLED = 0x533;
    protected static final int ACCOUNT_EXPIRED = 0x701;
    protected static final int PASSWORD_NEEDS_RESET = 0x773;
    protected static final int ACCOUNT_LOCKED = 0x775;

    protected final String domain;
    protected final String rootDn;
    protected final String url;

    protected boolean convertSubErrorCodesToExceptions;
    protected String searchFilter = "(&(objectClass=user)(userPrincipalName={0}))";

    // Only used to allow tests to substitute a mock LdapContext
    ContextFactory contextFactory = new ContextFactory();

    protected AbstractActiveDirectoryLdapAuthenticationProvider(final String domain, final String url, final String rootDn) {
        Assert.isTrue(StringUtils.hasText(url), "Url cannot be empty");
        this.domain = StringUtils.hasText(domain) ? domain.toLowerCase() : null;
        this.url = url;
        this.rootDn = StringUtils.hasText(rootDn) ? rootDn.toLowerCase() : null;
    }

    protected AbstractActiveDirectoryLdapAuthenticationProvider(final String domain, final String url) {
        Assert.isTrue(StringUtils.hasText(url), "Url cannot be empty");
        this.domain = StringUtils.hasText(domain) ? domain.toLowerCase() : null;
        this.url = url;
        rootDn = this.domain == null ? null : rootDnFromDomain(this.domain);
    }

    @Override
    protected DirContextOperations doAuthentication(UsernamePasswordAuthenticationToken auth) {
        DirContext ctx = bindAsUser(auth);

        try {
            return searchForUser(ctx, auth);
        } catch (NamingException e) {
            logger.error("Failed to locate directory entry for authenticated user: " + auth.getName(), e);
            throw badCredentials(e);
        } finally {
            LdapUtils.closeContext(ctx);
        }
    }

    protected DirContextOperations searchForUser(final DirContext context, final UsernamePasswordAuthenticationToken auth) throws NamingException {
        String username = auth.getName();
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        String bindPrincipal = createBindPrincipal(auth);
        String searchPrincipal = createSearchPrincipal(auth);

        String searchRoot = rootDn != null ? rootDn : searchRootFromPrincipal(bindPrincipal);

        try {
            return SpringSecurityLdapTemplate.searchForSingleEntryInternal(context,
                    searchControls, searchRoot, searchFilter,
                    new Object[]{searchPrincipal});
        } catch (IncorrectResultSizeDataAccessException incorrectResults) {
            // Search should never return multiple results if properly configured - just rethrow
            if (incorrectResults.getActualSize() != 0) {
                throw incorrectResults;
            }
            // If we found no results, then the username/password did not match
            UsernameNotFoundException userNameNotFoundException = new UsernameNotFoundException(
                    "User " + username + " not found in directory.", incorrectResults);
            throw badCredentials(userNameNotFoundException);
        }
    }

    private DirContext bindAsUser(final UsernamePasswordAuthenticationToken auth) {
        // TODO. add DNS lookup based on domain
        String password = (String) auth.getCredentials();

        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        String bindPrincipal = createBindPrincipal(auth);
        env.put(Context.SECURITY_PRINCIPAL, bindPrincipal);
        env.put(Context.PROVIDER_URL, url);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.OBJECT_FACTORIES, DefaultDirObjectFactory.class.getName());

        try {
            return contextFactory.createContext(env);
        } catch (NamingException e) {
            if ((e instanceof AuthenticationException) || (e instanceof OperationNotSupportedException)) {
                handleBindException(bindPrincipal, e);
                throw badCredentials(e);
            } else {
                throw LdapUtils.convertLdapException(e);
            }
        }
    }

    /**
     * Creates the principal string used to bind to the LDAP context.
     *
     * @param auth the authentication token
     * @return the principal string used to bind with to the LDAP context
     */
    protected abstract String createBindPrincipal(UsernamePasswordAuthenticationToken auth);

    /**
     * Creates the principal string used to search with in LDAP.
     *
     * @param auth the authentication token
     * @return the principal string used to search with in LDAP.
     */
    protected abstract String createSearchPrincipal(UsernamePasswordAuthenticationToken auth);

    /**
     * Creates the user authority list from the values of the {@code memberOf} attribute
     * obtained from the user's Active Directory entry.
     */
    @Override
    protected Collection<? extends GrantedAuthority> loadUserAuthorities(DirContextOperations userData, String username, String password) {
        String[] groups = userData.getStringAttributes("memberOf");

        if (groups == null) {
            logger.debug("No values for 'memberOf' attribute.");

            return AuthorityUtils.NO_AUTHORITIES;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("'memberOf' attribute values: " + Arrays.asList(groups));
        }

        ArrayList<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>(groups.length);

        for (String group : groups) {
            authorities.add(new SimpleGrantedAuthority(new DistinguishedName(group).removeLast().getValue()));
        }

        return authorities;
    }

    private String searchRootFromPrincipal(String bindPrincipal) {
        int atChar = bindPrincipal.lastIndexOf('@');

        if (atChar < 0) {
            logger.debug("User principal '" + bindPrincipal + "' does not contain the domain, and no domain has been configured");
            throw badCredentials();
        }

        return rootDnFromDomain(bindPrincipal.substring(atChar + 1, bindPrincipal.length()));
    }

    private String rootDnFromDomain(String domain) {
        String[] tokens = StringUtils.tokenizeToStringArray(domain, ".");
        StringBuilder root = new StringBuilder();

        for (String token : tokens) {
            if (root.length() > 0) {
                root.append(',');
            }
            root.append("dc=").append(token);
        }

        return root.toString();
    }

    private void handleBindException(String bindPrincipal, NamingException exception) {
        if (logger.isDebugEnabled()) {
            logger.debug("Authentication for " + bindPrincipal + " failed:" + exception);
        }

        int subErrorCode = parseSubErrorCode(exception.getMessage());

        if (subErrorCode <= 0) {
            logger.debug("Failed to locate AD-specific sub-error code in message");
            return;
        }

        logger.info("Active Directory authentication failed: " + subCodeToLogMessage(subErrorCode));

        if (convertSubErrorCodesToExceptions) {
            raiseExceptionForErrorCode(subErrorCode, exception);
        }
    }

    private int parseSubErrorCode(String message) {
        Matcher m = SUB_ERROR_CODE.matcher(message);

        if (m.matches()) {
            return Integer.parseInt(m.group(1), 16);
        }

        return -1;
    }

    private void raiseExceptionForErrorCode(int code, NamingException exception) {
        String hexString = Integer.toHexString(code);
        Throwable cause = new ActiveDirectoryAuthenticationException(hexString,
                exception.getMessage(), exception);
        switch (code) {
            case PASSWORD_EXPIRED:
                throw new CredentialsExpiredException(messages.getMessage(
                        "LdapAuthenticationProvider.credentialsExpired",
                        "User credentials have expired"), cause);
            case ACCOUNT_DISABLED:
                throw new DisabledException(messages.getMessage(
                        "LdapAuthenticationProvider.disabled", "User is disabled"), cause);
            case ACCOUNT_EXPIRED:
                throw new AccountExpiredException(messages.getMessage(
                        "LdapAuthenticationProvider.expired", "User account has expired"),
                        cause);
            case ACCOUNT_LOCKED:
                throw new LockedException(messages.getMessage(
                        "LdapAuthenticationProvider.locked", "User account is locked"), cause);
            default:
                throw badCredentials(cause);
        }
    }

    private String subCodeToLogMessage(int code) {
        switch (code) {
            case USERNAME_NOT_FOUND:
                return "User was not found in directory";
            case INVALID_PASSWORD:
                return "Supplied password was invalid";
            case NOT_PERMITTED:
                return "User not permitted to logon at this time";
            case PASSWORD_EXPIRED:
                return "Password has expired";
            case ACCOUNT_DISABLED:
                return "Account is disabled";
            case ACCOUNT_EXPIRED:
                return "Account expired";
            case PASSWORD_NEEDS_RESET:
                return "User must reset password";
            case ACCOUNT_LOCKED:
                return "Account locked";
        }

        return "Unknown (error code " + Integer.toHexString(code) + ")";
    }

    private BadCredentialsException badCredentials() {
        return new BadCredentialsException(messages.getMessage("LdapAuthenticationProvider.badCredentials", "Bad credentials"));
    }

    private BadCredentialsException badCredentials(Throwable cause) {
        return (BadCredentialsException) badCredentials().initCause(cause);
    }

    /**
     * By default, a failed authentication (LDAP error 49) will result in a
     * {@code BadCredentialsException}.
     * <p/>
     * If this property is set to {@code true}, the exception message from a failed bind
     * attempt will be parsed for the AD-specific error code and a
     * {@link CredentialsExpiredException}, {@link DisabledException},
     * {@link AccountExpiredException} or {@link LockedException} will be thrown for the
     * corresponding codes. All other codes will result in the default
     * {@code BadCredentialsException}.
     *
     * @param convertSubErrorCodesToExceptions {@code true} to raise an exception based on
     *                                         the AD error code.
     */
    public void setConvertSubErrorCodesToExceptions(boolean convertSubErrorCodesToExceptions) {
        this.convertSubErrorCodesToExceptions = convertSubErrorCodesToExceptions;
    }

    /**
     * The LDAP filter string to search for the user being authenticated. Occurrences of
     * {0} are replaced with the {@code username@domain}.
     * <p>
     * Defaults to: {@code (&(objectClass=user)(userPrincipalName= 0}))}
     * </p>
     *
     * @param searchFilter the filter string
     * @since 3.2.6
     */
    public void setSearchFilter(String searchFilter) {
        Assert.hasText(searchFilter, "searchFilter must have text");
        this.searchFilter = searchFilter;
    }

    static class ContextFactory {
        DirContext createContext(Hashtable<?, ?> env) throws NamingException {
            return new InitialLdapContext(env, null);
        }
    }
}
