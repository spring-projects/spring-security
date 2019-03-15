/*
 * Copyright 2010-2016 the original author or authors.
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
package samples.jaas;

import java.io.Serializable;
import java.security.Principal;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

/**
 * A LoginModule that will allow login if the username equals the password. Upon
 * successful authentication it adds the username as a Principal.
 *
 * @author Rob Winch
 */
public class UsernameEqualsPasswordLoginModule implements LoginModule {
	// ~ Instance fields
	// ================================================================================================

	private String password;
	private String username;
	private Subject subject;

	// ~ Methods
	// ========================================================================================================

	@Override
	public boolean abort() throws LoginException {
		return true;
	}

	@Override
	public boolean commit() throws LoginException {
		return true;
	}

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String, ?> sharedState, Map<String, ?> options) {
		this.subject = subject;

		try {
			NameCallback nameCallback = new NameCallback("prompt");
			PasswordCallback passwordCallback = new PasswordCallback("prompt", false);

			callbackHandler.handle(new Callback[] { nameCallback, passwordCallback });

			password = new String(passwordCallback.getPassword());
			username = nameCallback.getName();
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public boolean login() throws LoginException {
		if (username == null || !username.equals(password)) {
			throw new LoginException("username is not equal to password");
		}
		if ("".equals(username)) {
			throw new LoginException("username cannot be empty string");
		}

		subject.getPrincipals().add(new UsernamePrincipal(username));
		return true;
	}

	@Override
	public boolean logout() throws LoginException {
		return true;
	}

	private static class UsernamePrincipal implements Principal, Serializable {
		private final String username;

		public UsernamePrincipal(String username) {
			this.username = username;
		}

		@Override
		public String getName() {
			return username;
		}

		@Override
		public String toString() {
			return "Principal [name=" + getName() + "]";
		}

		private static final long serialVersionUID = 8049681145355488137L;
	}
}
