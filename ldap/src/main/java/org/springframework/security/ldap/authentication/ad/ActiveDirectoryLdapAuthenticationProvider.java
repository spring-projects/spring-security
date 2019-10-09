/*
 * Copyright 2002-2016 the original author or authors.
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

import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.support.DefaultDirObjectFactory;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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
import java.io.Serializable;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Specialized LDAP authentication provider which uses Active Directory configuration
 * conventions.
 * <p>
 * It will authenticate using the Active Directory <a
 * href="https://msdn.microsoft.com/en-us/library/ms680857%28VS.85%29.aspx">
 * {@code userPrincipalName}</a> or a custom {@link #setSearchFilter(String) searchFilter}
 * in the form {@code username@domain}. If the username does not already end with the
 * domain name, the {@code userPrincipalName} will be built by appending the configured
 * domain name to the username supplied in the authentication request. If no domain name
 * is configured, it is assumed that the username will always contain the domain name.
 * <p>
 * The user authorities are obtained from the data contained in the {@code memberOf}
 * attribute.
 *
 * <h3>Active Directory Sub-Error Codes</h3>
 *
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
 *
 * If you set the {@link #setConvertSubErrorCodesToExceptions(boolean)
 * convertSubErrorCodesToExceptions} property to {@code true}, the codes will also be used
 * to control the exception raised.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.1
 */
public final class ActiveDirectoryLdapAuthenticationProvider extends
		AbstractLdapAuthenticationProvider {
	private static final Pattern SUB_ERROR_CODE = Pattern
			.compile(".*data\\s([0-9a-f]{3,4}).*");

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

	/**
	 * @param domain the domain name (may be null or empty)
	 * @param url an LDAP url (or multiple URLs)
	 * @param rootDn the root DN (may be null or empty)
	 */
	public ActiveDirectoryLdapAuthenticationProvider(String domain, String url,
			String rootDn) {
		Assert.isTrue(StringUtils.hasText(url), "Url cannot be empty");
		this.domain = StringUtils.hasText(domain) ? domain.toLowerCase() : null;
		this.url = url;
		this.rootDn = StringUtils.hasText(rootDn) ? rootDn.toLowerCase() : null;
	}

	/**
	 * @param domain the domain name (may be null or empty)
	 * @param url an LDAP url (or multiple URLs)
	 */
	public ActiveDirectoryLdapAuthenticationProvider(String domain, String url) {
		Assert.isTrue(StringUtils.hasText(url), "Url cannot be empty");
		this.domain = StringUtils.hasText(domain) ? domain.toLowerCase() : null;
		this.url = url;
		rootDn = this.domain == null ? null : rootDnFromDomain(this.domain);
	}

	@Override
	protected DirContextOperations doAuthentication(
			UsernamePasswordAuthenticationToken auth) {
		String username = auth.getName();
		String password = (String) auth.getCredentials();

		DirContext ctx = bindAsUser(username, password);

		try {
			return searchForUser(ctx, username);
		}
		catch (NamingException e) {
			logger.error("Failed to locate directory entry for authenticated user: "
					+ username, e);
			throw badCredentials(e);
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
	protected Collection<? extends GrantedAuthority> loadUserAuthorities(
			DirContextOperations userData, String username, String password) {
		String[] groups = userData.getStringAttributes("memberOf");

		if (groups == null) {
			logger.debug("No values for 'memberOf' attribute.");

			return AuthorityUtils.NO_AUTHORITIES;
		}

		if (logger.isDebugEnabled()) {
			logger.debug("'memberOf' attribute values: " + Arrays.asList(groups));
		}

		ArrayList<GrantedAuthority> authorities = new ArrayList<>(
				groups.length);

		for (String group : groups) {
			authorities.add(new SimpleGrantedAuthority(new DistinguishedName(group)
					.removeLast().getValue()));
		}

		return authorities;
	}

	private DirContext bindAsUser(String username, String password) {
		// TODO. add DNS lookup based on domain
		final String bindUrl = url;

		Hashtable<String, Object> env = new Hashtable<>();
		env.put(Context.SECURITY_AUTHENTICATION, "simple");
		String bindPrincipal = createBindPrincipal(username);
		env.put(Context.SECURITY_PRINCIPAL, bindPrincipal);
		env.put(Context.PROVIDER_URL, bindUrl);
		env.put(Context.SECURITY_CREDENTIALS, password);
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.OBJECT_FACTORIES, DefaultDirObjectFactory.class.getName());
		env.putAll(this.contextEnvironmentProperties);

		try {
			return contextFactory.createContext(env);
		}
		catch (NamingException e) {
			if ((e instanceof AuthenticationException)
					|| (e instanceof OperationNotSupportedException)) {
				handleBindException(bindPrincipal, e);
				throw badCredentials(e);
			}
			else {
				throw LdapUtils.convertLdapException(e);
			}
		}
	}

	private void handleBindException(String bindPrincipal, NamingException exception) {
		if (logger.isDebugEnabled()) {
			logger.debug("Authentication for " + bindPrincipal + " failed:" + exception);
		}

		handleResolveObj(exception);

		int subErrorCode = parseSubErrorCode(exception.getMessage());

		if (subErrorCode <= 0) {
			logger.debug("Failed to locate AD-specific sub-error code in message");
			return;
		}

		logger.info("Active Directory authentication failed: "
				+ subCodeToLogMessage(subErrorCode));

		if (convertSubErrorCodesToExceptions) {
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
		return new BadCredentialsException(messages.getMessage(
				"LdapAuthenticationProvider.badCredentials", "Bad credentials"));
	}

	private BadCredentialsException badCredentials(Throwable cause) {
		return (BadCredentialsException) badCredentials().initCause(cause);
	}

	private DirContextOperations searchForUser(DirContext context, String username)
			throws NamingException {
		SearchControls searchControls = new SearchControls();
		searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

		String bindPrincipal = createBindPrincipal(username);
		String searchRoot = rootDn != null ? rootDn
				: searchRootFromPrincipal(bindPrincipal);

		try {
			return SpringSecurityLdapTemplate.searchForSingleEntryInternal(context,
					searchControls, searchRoot, searchFilter,
					new Object[] { bindPrincipal, username });
		}
		catch (IncorrectResultSizeDataAccessException incorrectResults) {
			// Search should never return multiple results if properly configured - just
			// rethrow
			if (incorrectResults.getActualSize() != 0) {
				throw incorrectResults;
			}
			// If we found no results, then the username/password did not match
			UsernameNotFoundException userNameNotFoundException = new UsernameNotFoundException(
					"User " + username + " not found in directory.", incorrectResults);
			throw badCredentials(userNameNotFoundException);
		}
	}

	private String searchRootFromPrincipal(String bindPrincipal) {
		int atChar = bindPrincipal.lastIndexOf('@');

		if (atChar < 0) {
			logger.debug("User principal '" + bindPrincipal
					+ "' does not contain the domain, and no domain has been configured");
			throw badCredentials();
		}

		return rootDnFromDomain(bindPrincipal.substring(atChar + 1,
				bindPrincipal.length()));
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

	String createBindPrincipal(String username) {
		if (domain == null || username.toLowerCase().endsWith(domain)) {
			return username;
		}

		return username + "@" + domain;
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
	 *
	 * @param convertSubErrorCodesToExceptions {@code true} to raise an exception based on
	 * the AD error code.
	 */
	public void setConvertSubErrorCodesToExceptions(
			boolean convertSubErrorCodesToExceptions) {
		this.convertSubErrorCodesToExceptions = convertSubErrorCodesToExceptions;
	}

	/**
	 * The LDAP filter string to search for the user being authenticated. Occurrences of
	 * {0} are replaced with the {@code username@domain}. Occurrences of {1} are replaced
	 * with the {@code username} only.
	 * <p>
	 * Defaults to: {@code (&(objectClass=user)(userPrincipalName={0}))}
	 * </p>
	 *
	 * @param searchFilter the filter string
	 *
	 * @since 3.2.6
	 */
	public void setSearchFilter(String searchFilter) {
		Assert.hasText(searchFilter, "searchFilter must have text");
		this.searchFilter = searchFilter;
	}

	/**
	 * Allows a custom environment properties to be used to create initial LDAP context.
	 *
	 * @param environment the additional environment parameters to use when creating the LDAP Context
	 */
	public void setContextEnvironmentProperties(Map<String, Object> environment) {
		Assert.notEmpty(environment, "environment must not be empty");
		this.contextEnvironmentProperties = new Hashtable<>(environment);
	}

	static class ContextFactory {
		DirContext createContext(Hashtable<?, ?> env) throws NamingException {
			return new InitialLdapContext(env, null);
		}
	}
}
