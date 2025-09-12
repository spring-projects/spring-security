/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.kerberos.authentication.sun;

import java.io.IOException;
import java.util.HashMap;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.kerberos.authentication.JaasSubjectHolder;
import org.springframework.security.kerberos.authentication.KerberosClient;

/**
 * Implementation of {@link KerberosClient} which uses the SUN JAAS login module, which is
 * included in the SUN JRE, it will not work with an IBM JRE. The whole configuration is
 * done in this class, no additional JAAS configuration is needed.
 *
 * @author Mike Wiesner
 * @author Bogdan Mustiata
 * @since 1.0
 */
public class SunJaasKerberosClient implements KerberosClient {

	private boolean debug = false;

	private boolean multiTier = false;

	private static final Log LOG = LogFactory.getLog(SunJaasKerberosClient.class);

	@Override
	public JaasSubjectHolder login(String username, String password) {
		LOG.debug("Trying to authenticate " + username + " with Kerberos");
		JaasSubjectHolder result;

		try {
			LoginContext loginContext = new LoginContext("", null,
					new KerberosClientCallbackHandler(username, password), new LoginConfig(this.debug));
			loginContext.login();

			Subject jaasSubject = loginContext.getSubject();

			if (LOG.isDebugEnabled()) {
				LOG.debug("Kerberos authenticated user: " + jaasSubject);
			}

			String validatedUsername = jaasSubject.getPrincipals().iterator().next().toString();
			Subject subjectCopy = JaasUtil.copySubject(jaasSubject);
			result = new JaasSubjectHolder(subjectCopy, validatedUsername);

			if (!this.multiTier) {
				loginContext.logout();
			}
		}
		catch (LoginException ex) {
			throw new BadCredentialsException("Kerberos authentication failed", ex);
		}

		return result;
	}

	public void setDebug(boolean debug) {
		this.debug = debug;
	}

	public void setMultiTier(boolean multiTier) {
		this.multiTier = multiTier;
	}

	private static final class LoginConfig extends Configuration {

		private boolean debug;

		private LoginConfig(boolean debug) {
			super();
			this.debug = debug;
		}

		@Override
		public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
			HashMap<String, String> options = new HashMap<String, String>();
			options.put("storeKey", "true");
			if (this.debug) {
				options.put("debug", "true");
			}

			return new AppConfigurationEntry[] {
					new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
							AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options), };
		}

	}

	static final class KerberosClientCallbackHandler implements CallbackHandler {

		private String username;

		private String password;

		private KerberosClientCallbackHandler(String username, String password) {
			this.username = username;
			this.password = password;
		}

		@Override
		public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
			for (Callback callback : callbacks) {
				if (callback instanceof NameCallback) {
					NameCallback ncb = (NameCallback) callback;
					ncb.setName(this.username);
				}
				else if (callback instanceof PasswordCallback) {
					PasswordCallback pwcb = (PasswordCallback) callback;
					pwcb.setPassword(this.password.toCharArray());
				}
				else {
					throw new UnsupportedCallbackException(callback,
							"We got a " + callback.getClass().getCanonicalName()
									+ ", but only NameCallback and PasswordCallback is supported");
				}
			}

		}

	}

}
