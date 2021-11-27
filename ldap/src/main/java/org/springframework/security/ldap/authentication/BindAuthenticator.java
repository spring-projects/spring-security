/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.ldap.authentication;

import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.ldap.NamingException;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.ldap.ppolicy.PasswordPolicyControl;
import org.springframework.security.ldap.ppolicy.PasswordPolicyControlExtractor;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An authenticator which binds as a user.
 *
 * @author Luke Taylor
 * @see AbstractLdapAuthenticator
 */
public class BindAuthenticator extends AbstractLdapAuthenticator {

	private static final Log logger = LogFactory.getLog(BindAuthenticator.class);

	/**
	 * Create an initialized instance using the {@link BaseLdapPathContextSource}
	 * provided.
	 * @param contextSource the BaseLdapPathContextSource instance against which bind
	 * operations will be performed.
	 */
	public BindAuthenticator(BaseLdapPathContextSource contextSource) {
		super(contextSource);
	}

	@Override
	public DirContextOperations authenticate(Authentication authentication) {
		DirContextOperations user = null;
		Assert.isInstanceOf(UsernamePasswordAuthenticationToken.class, authentication,
				"Can only process UsernamePasswordAuthenticationToken objects");
		String username = authentication.getName();
		String password = (String) authentication.getCredentials();
		if (!StringUtils.hasLength(password)) {
			logger.debug(LogMessage.format("Failed to authenticate since no credentials provided"));
			throw new BadCredentialsException(
					this.messages.getMessage("BindAuthenticator.emptyPassword", "Empty Password"));
		}
		// If DN patterns are configured, try authenticating with them directly
		for (String dn : getUserDns(username)) {
			user = bindWithDn(dn, username, password);
			if (user != null) {
				break;
			}
		}
		if (user == null) {
			logger.debug(LogMessage.of(() -> "Failed to bind with any user DNs " + getUserDns(username)));
		}
		// Otherwise use the configured search object to find the user and authenticate
		// with the returned DN.
		if (user == null && getUserSearch() != null) {
			logger.trace("Searching for user using " + getUserSearch());
			DirContextOperations userFromSearch = getUserSearch().searchForUser(username);
			user = bindWithDn(userFromSearch.getDn().toString(), username, password, userFromSearch.getAttributes());
			if (user == null) {
				logger.debug("Failed to find user using " + getUserSearch());
			}
		}
		if (user == null) {
			throw new BadCredentialsException(
					this.messages.getMessage("BindAuthenticator.badCredentials", "Bad credentials"));
		}
		return user;
	}

	private DirContextOperations bindWithDn(String userDnStr, String username, String password) {
		return bindWithDn(userDnStr, username, password, null);
	}

	private DirContextOperations bindWithDn(String userDnStr, String username, String password, Attributes attrs) {
		BaseLdapPathContextSource ctxSource = (BaseLdapPathContextSource) getContextSource();
		DistinguishedName userDn = new DistinguishedName(userDnStr);
		DistinguishedName fullDn = new DistinguishedName(userDn);
		fullDn.prepend(ctxSource.getBaseLdapPath());
		logger.trace(LogMessage.format("Attempting to bind as %s", fullDn));
		DirContext ctx = null;
		try {
			ctx = getContextSource().getContext(fullDn.toString(), password);
			// Check for password policy control
			PasswordPolicyControl ppolicy = PasswordPolicyControlExtractor.extractControl(ctx);
			if (attrs == null || attrs.size() == 0) {
				attrs = ctx.getAttributes(userDn, getUserAttributes());
			}
			DirContextAdapter result = new DirContextAdapter(attrs, userDn, ctxSource.getBaseLdapPath());
			if (ppolicy != null) {
				result.setAttributeValue(ppolicy.getID(), ppolicy);
			}
			logger.debug(LogMessage.format("Bound %s", fullDn));
			return result;
		}
		catch (NamingException ex) {
			// This will be thrown if an invalid user name is used and the method may
			// be called multiple times to try different names, so we trap the exception
			// unless a subclass wishes to implement more specialized behaviour.
			if ((ex instanceof org.springframework.ldap.AuthenticationException)
					|| (ex instanceof org.springframework.ldap.OperationNotSupportedException)) {
				handleBindException(userDnStr, username, ex);
			}
			else {
				throw ex;
			}
		}
		catch (javax.naming.NamingException ex) {
			throw LdapUtils.convertLdapException(ex);
		}
		finally {
			LdapUtils.closeContext(ctx);
		}
		return null;
	}

	/**
	 * Allows subclasses to inspect the exception thrown by an attempt to bind with a
	 * particular DN. The default implementation just reports the failure to the debug
	 * logger.
	 */
	protected void handleBindException(String userDn, String username, Throwable cause) {
		logger.trace(LogMessage.format("Failed to bind as %s", userDn), cause);
	}

}
