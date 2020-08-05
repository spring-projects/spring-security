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

package org.springframework.security.authentication.jaas;

import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

/**
 * @author Ray Krueger
 */
public class TestLoginModule implements LoginModule {

	// ~ Instance fields
	// ================================================================================================

	private String password;

	private String user;

	private Subject subject;

	// ~ Methods
	// ========================================================================================================

	public boolean abort() {
		return true;
	}

	public boolean commit() {
		return true;
	}

	@SuppressWarnings("unchecked")
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map sharedState, Map options) {
		this.subject = subject;

		try {
			TextInputCallback textCallback = new TextInputCallback("prompt");
			NameCallback nameCallback = new NameCallback("prompt");
			PasswordCallback passwordCallback = new PasswordCallback("prompt", false);

			callbackHandler.handle(new Callback[] { textCallback, nameCallback, passwordCallback });

			password = new String(passwordCallback.getPassword());
			user = nameCallback.getName();
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public boolean login() throws LoginException {
		if (!user.equals("user")) {
			throw new LoginException("Bad User");
		}

		if (!password.equals("password")) {
			throw new LoginException("Bad Password");
		}

		subject.getPrincipals().add(() -> "TEST_PRINCIPAL");

		subject.getPrincipals().add(() -> "NULL_PRINCIPAL");

		return true;
	}

	public boolean logout() {
		return true;
	}

}
