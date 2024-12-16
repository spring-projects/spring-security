/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.ldap.authentication.ad;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.OperationNotSupportedException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.InitialLdapContext;

import org.springframework.core.log.LogMessage;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.CommunicationException;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.DefaultDirObjectFactory;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticationProvider;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Specialized LDAP authentication provider which uses Active Directory configuration
 * conventions.
 * <p>
 * It will authenticate using the Active Directory
 * <a href="https://msdn.microsoft.com/en-us/library/ms680857%28VS.85%29.aspx">
 * {@code userPrincipalName}</a> or a custom {@link #setSearchFilter(String) searchFilter}
 * in the form {@code username@domain}. If the username does not already end with the
 * domain name, the {@code userPrincipalName} will be built by appending the configured
 * domain name to the username supplied in the authentication request. If no domain name
 * is configured, it is assumed that the username will always contain the domain name.
 * <p>
 * The user authorities are obtained from the data contained in the {@code memberOf}
 * attribute.
 * <p>
 * <h3>Active Directory Sub-Error Codes</h3>
 * <p>
 * When an authentication fails, resulting in a standard LDAP 49 error code, Active
 * Directory also supplies its own sub-error codes within the error message. These will be
 * used to provide additional log information on why an authentication has failed. Typical
 * examples are
 *
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
 * <p>
 * If you set the {@link #setConvertSubErrorCodesToExceptions(boolean)
 * convertSubErrorCodesToExceptions} property to {@code true}, the codes will also be used
 * to control the exception raised.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @author Roman Zabaluev
 * @since 3.1
 */
public final class ActiveDirectoryLdapAuthenticationProvider extends AbstractLdapAuthenticationProvider {

	private static final Pattern SUB_ERROR_CODE = Pattern.compile(".*data\\s([0-9a-f]{3,4}).*");

	// Error codes
	private static final int USERNAME_NOT_FOUND = 0x525;

	private static final int INVALID_PASSWORD = 0x52e;

	private static final int NOT_PERMITTED = 0x530;

	private static final int PASSWORD_EXPIRED = 0x532;

	private static final int ACCOUNT_DISABLED = 0x533;

	private static final int ACCOUNT_EXPIRED = 0x701;

	private static final int PASSWORD_NEEDS_RESET = 0x773;

	private static final int ACCOUNT_LOCKED = 0x775;

	private final String domain;

	private final String rootDn;

	private final String url;

	private boolean convertSubErrorCodesToExceptions;

	private String searchFilter = "(&(objectClass=user)(userPrincipalName={0}))";

	private Map<String, Object> contextEnvironmentProperties = new HashMap<>();

	// Only used to allow tests to substitute a mock LdapContext
	ContextFactory contextFactory = new ContextFactory();

	private LdapAuthoritiesPopulator authoritiesPopulator = new DefaultActiveDirectoryAuthoritiesPopulator();

	/**
	 * @param domain the domain name (can be null or empty)
	 * @param url an LDAP url (or multiple space-delimited URLs).
	 * @param rootDn the root DN (can be null or empty)
	 * @see <a href="https://docs.oracle.com/javase/jndi/tutorial/ldap/misc/url.html">JNDI
	 * URL format documentation</a>
	 */
	public ActiveDirectoryLdapAuthenticationProvider(String domain, String url, String rootDn) {
		Assert.isTrue(StringUtils.hasText(url), "Url cannot be empty");
		this.domain = StringUtils.hasText(domain) ? domain.toLowerCase(Locale.ROOT) : null;
		this.url = url;
		this.rootDn = StringUtils.hasText(rootDn) ? rootDn.toLowerCase(Locale.ROOT) : null;
	}

	/**
	 * @param domain the domain name (can be null or empty)
	 * @param url an LDAP url (or multiple URLs)
	 */
	public ActiveDirectoryLdapAuthenticationProvider(String domain, String url) {
		Assert.isTrue(StringUtils.hasText(url), "Url cannot be empty");
		this.domain = StringUtils.hasText(domain) ? domain.toLowerCase(Locale.ROOT) : null;
		this.url = url;
		this.rootDn = (this.domain != null) ? rootDnFromDomain(this.domain) : null;
	}

	@Override
	protected DirContextOperations doAuthentication(UsernamePasswordAuthenticationToken auth) {
		String username = auth.getName();
		String password = (String) auth.getCredentials();
		DirContext ctx = null;
		try {
			ctx = bindAsUser(username, password);
			return searchForUser(ctx, username);
		}
		catch (CommunicationException ex) {
			throw badLdapConnection(ex);
		}
		catch (NamingException ex) {
			this.logger.error("Failed to locate directory entry for authenticated user: " + username, ex);
			throw badCredentials(ex);
		}
		finally {
			LdapUtils.closeContext(ctx);
		}
	}

	/**
	 * Creates the user authority list from the values of the {@code memberOf} attribute
	 * obtained from the user's Active Directory entry.
	 */
	@Override
	protected Collection<? extends GrantedAuthority> loadUserAuthorities(DirContextOperations userData, String username,
			String password) {
		return this.authoritiesPopulator.getGrantedAuthorities(userData, username);
	}

	private DirContext bindAsUser(String username, String password) {
		// TODO. add DNS lookup based on domain
		Hashtable<String, Object> env = new Hashtable<>();
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		String bindPrincipal = createBindPrincipal(username);
		env.put(Context.SECURITY_PRINCIPAL, bindPrincipal);
		env.put(Context.PROVIDER_URL, this.url);
		env.put(Context.SECURITY_CREDENTIALS, password);
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.OBJECT_FACTORIES, DefaultDirObjectFactory.class.getName());
		env.putAll(this.contextEnvironmentProperties);
		try {
			return this.contextFactory.createContext(env);
		}
		catch (NamingException ex) {
			if ((ex instanceof AuthenticationException) || (ex instanceof OperationNotSupportedException)) {
				handleBindException(bindPrincipal, ex);
				throw badCredentials(ex);
			}
			throw LdapUtils.convertLdapException(ex);
		}
	}

	private void handleBindException(String bindPrincipal, NamingException exception) {
		this.logger.debug(LogMessage.format("Authentication for %s failed:%s", bindPrincipal, exception));
		handleResolveObj(exception);
		int subErrorCode = parseSubErrorCode(exception.getMessage());
		if (subErrorCode <= 0) {
			this.logger.debug("Failed to locate AD-specific sub-error code in message");
			return;
		}
		this.logger
			.info(LogMessage.of(() -> "Active Directory authentication failed: " + subCodeToLogMessage(subErrorCode)));
		if (this.convertSubErrorCodesToExceptions) {
			raiseExceptionForErrorCode(subErrorCode, exception);
		}
	}

	private void handleResolveObj(NamingException exception) {
		Object resolvedObj = exception.getResolvedObj();
		boolean serializable = resolvedObj instanceof Serializable;
		if (resolvedObj != null && !serializable) {
			exception.setResolvedObj(null);
		}
	}

	private int parseSubErrorCode(String message) {
		Matcher matcher = SUB_ERROR_CODE.matcher(message);
		if (matcher.matches()) {
			return Integer.parseInt(matcher.group(1), 16);
		}
		return -1;
	}

	private void raiseExceptionForErrorCode(int code, NamingException exception) {
		String hexString = Integer.toHexString(code);
		Throwable cause = new ActiveDirectoryAuthenticationException(hexString, exception.getMessage(), exception);
		switch (code) {
			case PASSWORD_EXPIRED -> throw new CredentialsExpiredException(this.messages
				.getMessage("LdapAuthenticationProvider.credentialsExpired", "User credentials have expired"), cause);
			case ACCOUNT_DISABLED -> throw new DisabledException(
					this.messages.getMessage("LdapAuthenticationProvider.disabled", "User is disabled"), cause);
			case ACCOUNT_EXPIRED -> throw new AccountExpiredException(
					this.messages.getMessage("LdapAuthenticationProvider.expired", "User account has expired"), cause);
			case ACCOUNT_LOCKED -> throw new LockedException(
					this.messages.getMessage("LdapAuthenticationProvider.locked", "User account is locked"), cause);
			default -> throw badCredentials(cause);
		}
	}

	private String subCodeToLogMessage(int code) {
		return switch (code) {
			case USERNAME_NOT_FOUND -> "User was not found in directory";
			case INVALID_PASSWORD -> "Supplied password was invalid";
			case NOT_PERMITTED -> "User not permitted to logon at this time";
			case PASSWORD_EXPIRED -> "Password has expired";
			case ACCOUNT_DISABLED -> "Account is disabled";
			case ACCOUNT_EXPIRED -> "Account expired";
			case PASSWORD_NEEDS_RESET -> "User must reset password";
			case ACCOUNT_LOCKED -> "Account locked";
			default -> "Unknown (error code " + Integer.toHexString(code) + ")";
		};
	}

	private BadCredentialsException badCredentials() {
		return new BadCredentialsException(
				this.messages.getMessage("LdapAuthenticationProvider.badCredentials", "Bad credentials"));
	}

	private BadCredentialsException badCredentials(Throwable cause) {
		return (BadCredentialsException) badCredentials().initCause(cause);
	}

	private InternalAuthenticationServiceException badLdapConnection(Throwable cause) {
		return new InternalAuthenticationServiceException(this.messages
			.getMessage("LdapAuthenticationProvider.badLdapConnection", "Connection to LDAP server failed."), cause);
	}

	private DirContextOperations searchForUser(DirContext context, String username) throws NamingException {
		SearchControls searchControls = new SearchControls();
		searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		String bindPrincipal = createBindPrincipal(username);
		String searchRoot = (this.rootDn != null) ? this.rootDn : searchRootFromPrincipal(bindPrincipal);

		try {
			return SpringSecurityLdapTemplate.searchForSingleEntryInternal(context, searchControls, searchRoot,
					this.searchFilter, new Object[] { bindPrincipal, username });
		}
		catch (CommunicationException ex) {
			throw badLdapConnection(ex);
		}
		catch (IncorrectResultSizeDataAccessException ex) {
			// Search should never return multiple results if properly configured -
			if (ex.getActualSize() != 0) {
				throw ex;
			}
			// If we found no results, then the username/password did not match
			UsernameNotFoundException userNameNotFoundException = new UsernameNotFoundException(
					"User " + username + " not found in directory.", ex);
			throw badCredentials(userNameNotFoundException);
		}
	}

	private String searchRootFromPrincipal(String bindPrincipal) {
		int atChar = bindPrincipal.lastIndexOf('@');
		if (atChar < 0) {
			this.logger.debug("User principal '" + bindPrincipal
					+ "' does not contain the domain, and no domain has been configured");
			throw badCredentials();
		}
		return rootDnFromDomain(bindPrincipal.substring(atChar + 1));
	}

	private String rootDnFromDomain(String domain) {
		String[] tokens = StringUtils.tokenizeToStringArray(domain, ".");
		StringBuilder root = new StringBuilder();
		for (String token : tokens) {
			if (!root.isEmpty()) {
				root.append(',');
			}
			root.append("dc=").append(token);
		}
		return root.toString();
	}

	String createBindPrincipal(String username) {
		if (this.domain == null || username.toLowerCase(Locale.ROOT).endsWith(this.domain)) {
			return username;
		}
		return username + "@" + this.domain;
	}

	/**
	 * By default, a failed authentication (LDAP error 49) will result in a
	 * {@code BadCredentialsException}.
	 * <p>
	 * If this property is set to {@code true}, the exception message from a failed bind
	 * attempt will be parsed for the AD-specific error code and a
	 * {@link CredentialsExpiredException}, {@link DisabledException},
	 * {@link AccountExpiredException} or {@link LockedException} will be thrown for the
	 * corresponding codes. All other codes will result in the default
	 * {@code BadCredentialsException}.
	 * @param convertSubErrorCodesToExceptions {@code true} to raise an exception based on
	 * the AD error code.
	 */
	public void setConvertSubErrorCodesToExceptions(boolean convertSubErrorCodesToExceptions) {
		this.convertSubErrorCodesToExceptions = convertSubErrorCodesToExceptions;
	}

	/**
	 * The LDAP filter string to search for the user being authenticated. Occurrences of
	 * {0} are replaced with the {@code username@domain}. Occurrences of {1} are replaced
	 * with the {@code username} only.
	 * <p>
	 * Defaults to: {@code (&(objectClass=user)(userPrincipalName={0}))}
	 * </p>
	 * @param searchFilter the filter string
	 * @since 3.2.6
	 */
	public void setSearchFilter(String searchFilter) {
		Assert.hasText(searchFilter, "searchFilter must have text");
		this.searchFilter = searchFilter;
	}

	/**
	 * Allows a custom environment properties to be used to create initial LDAP context.
	 * @param environment the additional environment parameters to use when creating the
	 * LDAP Context
	 */
	public void setContextEnvironmentProperties(Map<String, Object> environment) {
		Assert.notEmpty(environment, "environment must not be empty");
		this.contextEnvironmentProperties = new Hashtable<>(environment);
	}

	/**
	 * Set the strategy for obtaining the authorities for a given user after they've been
	 * authenticated. Consider adjusting this if you require a custom authorities mapping
	 * algorithm different from a default one. The default value is
	 * DefaultActiveDirectoryAuthoritiesPopulator.
	 * @param authoritiesPopulator authorities population strategy
	 * @since 6.3
	 */
	public void setAuthoritiesPopulator(LdapAuthoritiesPopulator authoritiesPopulator) {
		Assert.notNull(authoritiesPopulator, "authoritiesPopulator must not be null");
		this.authoritiesPopulator = authoritiesPopulator;
	}

	static class ContextFactory {

		DirContext createContext(Hashtable<?, ?> env) throws NamingException {
			return new InitialLdapContext(env, null);
		}

	}

}
