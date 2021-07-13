/*
 * Copyright 2012-2016 the original author or authors.
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.NamingException;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticator;
import org.springframework.security.ldap.authentication.AuthenticationPrincipalDecorator;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An Active Directory implementation of a {@link LdapAuthenticator}.
 *
 * @author Joe Grandja
 *
 * @see AbstractLdapAuthenticator
 * @see AuthenticationPrincipalDecorator
 *
 */
public final class ActiveDirectoryLdapAuthenticator extends AbstractLdapAuthenticator {
	private static final Logger logger = LoggerFactory.getLogger(ActiveDirectoryLdapAuthenticator.class);

	// Active Directory sub-error codes
	private static final int USERNAME_NOT_FOUND = 0x525;
	private static final int INVALID_PASSWORD = 0x52e;
	private static final int NOT_PERMITTED = 0x530;
	private static final int PASSWORD_EXPIRED = 0x532;
	private static final int ACCOUNT_DISABLED = 0x533;
	private static final int ACCOUNT_EXPIRED = 0x701;
	private static final int PASSWORD_NEEDS_RESET = 0x773;
	private static final int ACCOUNT_LOCKED = 0x775;

	private static final Pattern SUB_ERROR_CODE_PATTERN = Pattern.compile(".*data\\s([0-9a-f]{3,4}).*");
	private boolean convertSubErrorCodeToException;
	private String managerDn;
	private String managerPassword;
	private String searchBase;
	private String searchFilter;
	private String passwordAttributeName = "userPassword";
	private PasswordEncoder passwordEncoder = NoOpPasswordEncoder.getInstance();
	private AuthenticationPrincipalDecorator authenticationPrincipalDecorator = new DefaultAuthenticationPrincipalDecorator();

	public ActiveDirectoryLdapAuthenticator(BaseLdapPathContextSource contextSource) {
		super(contextSource);
	}

	public DirContextOperations authenticate(Authentication authentication) {
		String principal = authentication.getName();
		String credentials = (String) authentication.getCredentials();

		principal = this.authenticationPrincipalDecorator.decorate(principal);

		DirContextOperations result = null;
		try {
			if (managerCredentialsAvailable()) {
				result = bindAsManager(principal, credentials);
			} else {
				result = bindAsUser(principal, credentials);
			}
		} catch (javax.naming.NamingException ex) {
			throw LdapUtils.convertLdapException(ex);
		}

		return result;
	}

	private DirContextOperations bindAsUser(String principal, String credentials) throws javax.naming.NamingException {
		DirContext dirContext = null;
		DirContextOperations result = null;

		try {
			// If DN patterns are configured, try authenticating with them directly
			for (String principalDN : getUserDns(principal)) {
				try {
					dirContext = bindWithDN(principalDN, credentials);
				} catch (NamingException ne) {
					logger.warn("Failed to bind " + principalDN, ne);
					continue;
				}
				if (dirContext != null) {
					try {
						Attributes attrs = dirContext.getAttributes(principalDN, getUserAttributes());
						BaseLdapPathContextSource contextSource = (BaseLdapPathContextSource) getContextSource();
						result = new DirContextAdapter(attrs,
							LdapUtils.newLdapName(principalDN), contextSource.getBaseLdapName());
						break;
					} catch (javax.naming.NamingException ne) {
						// Allow further attempts at binding
						logger.warn("Failed to obtain attributes for User DN " + principalDN, ne);
					}
				}
			}

			// Otherwise use the configured search object to find the user and authenticate
			if (result == null && getUserSearch() != null) {
				try {
					result = getUserSearch().searchForUser(principal);
				} catch (IncorrectResultSizeDataAccessException incorrectResults) {
					logger.warn("Search failed for principal " + principal, incorrectResults);
				}
			}

		} finally {
			if (dirContext != null) {
				LdapUtils.closeContext(dirContext);
			}
		}

		if (result == null) {
			throw badCredentials();
		}

		return result;
	}

	private DirContextOperations bindAsManager(String principal, String credentials) throws javax.naming.NamingException {
		DirContext dirContext = null;
		DirContextOperations result = null;

		try {
			logger.debug("Attempting to bind as manager");
			dirContext = bindWithDN(this.managerDn, this.managerPassword);

			SearchControls searchControls = new SearchControls();
			searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
			result = SpringSecurityLdapTemplate.searchForSingleEntryInternal(dirContext, searchControls,
				(this.searchBase == null ? "" : this.searchBase), this.searchFilter, new Object[] {principal});

			// Validate password
			Object passwordAttrValue = result.getObjectAttribute(this.passwordAttributeName);
			if (!passwordEncoder.matches(credentials, new String((byte[]) passwordAttrValue))) {
				throw badCredentials();
			}

		} catch (IncorrectResultSizeDataAccessException incorrectResults) {
			if (incorrectResults.getActualSize() == 0) {
				throw usernameNotFound(principal);
			}
			// Search should never return multiple results if properly configured
			throw badCredentials(incorrectResults);
		} finally {
			if (dirContext != null) {
				LdapUtils.closeContext(dirContext);
			}
		}

		return result;
	}

	private DirContext bindWithDN(String principalDN, String credentials) {
		BaseLdapPathContextSource contextSource = (BaseLdapPathContextSource) getContextSource();
		LdapName baseDN = contextSource.getBaseLdapName();
		if (!principalDN.endsWith(baseDN.toString())) {
			principalDN = LdapUtils.prepend(LdapUtils.newLdapName(principalDN), baseDN).toString();
		}
		logger.debug("Attempting to bind " + principalDN);

		DirContext context = null;
		try {
			context = contextSource.getContext(principalDN, credentials);
		} catch (NamingException ne) {
			if (ne.getCause() instanceof javax.naming.NamingException) {
				handleBindException((javax.naming.NamingException) ne.getCause());
			}
			throw ne;
		}

		return context;
	}

	private boolean managerCredentialsAvailable() {
		return StringUtils.hasText(this.managerDn) && StringUtils.hasText(this.managerPassword);
	}

	private String domainFromBaseDN() {
		String domain = "";
		BaseLdapPathContextSource contextSource = (BaseLdapPathContextSource) getContextSource();
		List<Rdn> rdns = new ArrayList<Rdn>(contextSource.getBaseLdapName().getRdns());
		if (!rdns.isEmpty()) {
			Collections.reverse(rdns);
			for (Rdn rdn : rdns) {
				domain += rdn.getValue() + ".";
			}
			domain = domain.substring(0, domain.length() - 1);
		}
		return domain;
	}

	private BadCredentialsException badCredentials() {
		return new BadCredentialsException(messages.getMessage(
			"LdapAuthenticationProvider.badCredentials", "Bad credentials"));
	}

	private BadCredentialsException badCredentials(Throwable cause) {
		return (BadCredentialsException) badCredentials().initCause(cause);
	}

	private UsernameNotFoundException usernameNotFound(String principal) {
		throw new UsernameNotFoundException("User " + principal
			+ " not found in directory.");
	}

	private void handleBindException(javax.naming.NamingException ne) {
		int subErrorCode = parseSubErrorCode(ne.getMessage());
		if (subErrorCode <= 0) {
			logger.debug("Failed to locate Active Directory specific sub-error code");
			return;
		}
		logger.info("Active Directory bind authentication failed: " + toErrorMessage(subErrorCode));

		if (this.convertSubErrorCodeToException) {
			raiseException(subErrorCode, ne);
		}
	}

	private int parseSubErrorCode(String message) {
		Matcher matcher = SUB_ERROR_CODE_PATTERN.matcher(message);
		if (matcher.matches()) {
			return Integer.parseInt(matcher.group(1), 16);
		}
		return -1;
	}

	private String toErrorMessage(int errorCode) {
		switch (errorCode) {
			case USERNAME_NOT_FOUND:
				return "User was not found in directory";
			case INVALID_PASSWORD:
				return "Supplied password is invalid";
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
			default:
				return "Unknown errorCode " + errorCode + " (" + Integer.toHexString(errorCode) + ")";
		}
	}

	private void raiseException(int errorCode, javax.naming.NamingException ne) {
		Throwable cause = new ActiveDirectoryAuthenticationException(
			Integer.toHexString(errorCode), ne.getMessage(), ne);
		switch (errorCode) {
			case PASSWORD_EXPIRED:
				throw new CredentialsExpiredException(messages.getMessage(
					"LdapAuthenticationProvider.credentialsExpired", "User credentials have expired"), cause);
			case ACCOUNT_DISABLED:
				throw new DisabledException(messages.getMessage(
					"LdapAuthenticationProvider.disabled", "User account is disabled"), cause);
			case ACCOUNT_EXPIRED:
				throw new AccountExpiredException(messages.getMessage(
					"LdapAuthenticationProvider.expired", "User account has expired"), cause);
			case ACCOUNT_LOCKED:
				throw new LockedException(messages.getMessage(
					"LdapAuthenticationProvider.locked", "User account is locked"), cause);
			default:
				throw badCredentials(cause);
		}
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		super.afterPropertiesSet();
		if (StringUtils.hasText(this.managerDn)) {
			Assert.notNull(this.managerPassword, "managerPassword cannot be null when managerDn is provided");
			Assert.notNull(this.searchFilter, "searchFilter cannot be null when managerDn is provided");
		}
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
	 * @param convertSubErrorCodeToException {@code true} to raise an exception based on
	 * the AD error code.
	 */
	public final void setConvertSubErrorCodeToException(boolean convertSubErrorCodeToException) {
		this.convertSubErrorCodeToException = convertSubErrorCodeToException;
	}

	public final void setManagerDn(String managerDn) {
		Assert.notNull(managerDn, "managerDn is null");
		this.managerDn = managerDn;
	}

	public final void setManagerPassword(String managerPassword) {
		Assert.notNull(managerPassword, "managerPassword is null");
		this.managerPassword = managerPassword;
	}

	public final void setSearchBase(String searchBase) {
		Assert.notNull(searchBase, "searchBase is null");
		this.searchBase = searchBase;
	}

	public final void setSearchFilter(String searchFilter) {
		Assert.notNull(searchFilter, "searchFilter is null");
		this.searchFilter = searchFilter;
	}

	public final void setPasswordAttributeName(String passwordAttributeName) {
		Assert.notNull(passwordAttributeName, "passwordAttributeName is null");
		this.passwordAttributeName = passwordAttributeName;
	}

	public final void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		Assert.notNull(passwordEncoder, "passwordEncoder is null");
		this.passwordEncoder = passwordEncoder;
	}

	public final void setAuthenticationPrincipalDecorator(AuthenticationPrincipalDecorator authenticationPrincipalDecorator) {
		Assert.notNull(authenticationPrincipalDecorator, "authenticationPrincipalDecorator is null");
		this.authenticationPrincipalDecorator = authenticationPrincipalDecorator;
	}

	private class DefaultAuthenticationPrincipalDecorator implements AuthenticationPrincipalDecorator {
		@Override
		public String decorate(String principal) {
			String domain = domainFromBaseDN();
			if (!principal.endsWith(domain)) {
				principal += "@" + domain;
			}
			return principal;
		}
	}
}
