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

package org.springframework.security.ldap.ppolicy;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;

import org.springframework.core.log.LogMessage;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;

/**
 * Extended version of the <tt>DefaultSpringSecurityContextSource</tt> which adds support
 * for the use of {@link PasswordPolicyControl} to make use of user account data stored in
 * the directory.
 * <p>
 * When binding with specific username (not the <tt>userDn</tt>) property it will connect
 * first as the userDn, then reconnect as the user in order to retrieve any
 * password-policy control sent with the response, even if an exception occurs.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class PasswordPolicyAwareContextSource extends DefaultSpringSecurityContextSource {

	public PasswordPolicyAwareContextSource(String providerUrl) {
		super(providerUrl);
	}

	@Override
	public DirContext getContext(String principal, String credentials) throws PasswordPolicyException {
		if (principal.equals(getUserDn())) {
			return super.getContext(principal, credentials);
		}
		this.logger.trace(LogMessage.format("Binding as %s, prior to reconnect as user %s", getUserDn(), principal));
		// First bind as manager user before rebinding as the specific principal.
		LdapContext ctx = (LdapContext) super.getContext(getUserDn(), getPassword());
		Control[] rctls = { new PasswordPolicyControl(false) };
		try {
			ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, principal);
			ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, credentials);
			ctx.reconnect(rctls);
		}
		catch (javax.naming.NamingException ex) {
			PasswordPolicyResponseControl ctrl = PasswordPolicyControlExtractor.extractControl(ctx);
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format("Failed to bind with %s", ctrl), ex);
			}
			LdapUtils.closeContext(ctx);
			if (ctrl != null && ctrl.isLocked()) {
				throw new PasswordPolicyException(ctrl.getErrorStatus());
			}
			throw LdapUtils.convertLdapException(ex);
		}
		this.logger.debug(LogMessage.of(() -> "Bound with " + PasswordPolicyControlExtractor.extractControl(ctx)));
		return ctx;
	}

	@Override
	@SuppressWarnings("unchecked")
	protected Hashtable getAuthenticatedEnv(String principal, String credentials) {
		Hashtable<String, Object> env = super.getAuthenticatedEnv(principal, credentials);
		env.put(LdapContext.CONTROL_FACTORIES, PasswordPolicyControlFactory.class.getName());
		return env;
	}

}
