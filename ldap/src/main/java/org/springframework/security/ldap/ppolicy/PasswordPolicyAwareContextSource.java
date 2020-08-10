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
package org.springframework.security.ldap.ppolicy;

import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.directory.DirContext;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;

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
		if (principal.equals(userDn)) {
			return super.getContext(principal, credentials);
		}

		final boolean debug = logger.isDebugEnabled();

		if (debug) {
			logger.debug("Binding as '" + userDn + "', prior to reconnect as user '" + principal + "'");
		}

		// First bind as manager user before rebinding as the specific principal.
		LdapContext ctx = (LdapContext) super.getContext(userDn, password);

		Control[] rctls = { new PasswordPolicyControl(false) };

		try {
			ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, principal);
			ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, credentials);
			ctx.reconnect(rctls);
		}
		catch (javax.naming.NamingException ne) {
			PasswordPolicyResponseControl ctrl = PasswordPolicyControlExtractor.extractControl(ctx);
			if (debug) {
				logger.debug("Failed to obtain context", ne);
				logger.debug("Password policy response: " + ctrl);
			}

			LdapUtils.closeContext(ctx);

			if (ctrl != null) {
				if (ctrl.isLocked()) {
					throw new PasswordPolicyException(ctrl.getErrorStatus());
				}
			}

			throw LdapUtils.convertLdapException(ne);
		}

		if (debug) {
			logger.debug("PPolicy control returned: " + PasswordPolicyControlExtractor.extractControl(ctx));
		}

		return ctx;
	}

	@Override
	@SuppressWarnings("unchecked")
	protected Hashtable getAuthenticatedEnv(String principal, String credentials) {
		Hashtable env = super.getAuthenticatedEnv(principal, credentials);

		env.put(LdapContext.CONTROL_FACTORIES, PasswordPolicyControlFactory.class.getName());

		return env;
	}

}
