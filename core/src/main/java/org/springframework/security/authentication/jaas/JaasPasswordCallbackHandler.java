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

import org.springframework.security.core.Authentication;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

/**
 * The most basic Callbacks to be handled when using a LoginContext from JAAS, are the
 * NameCallback and PasswordCallback. Spring Security provides the
 * JaasPasswordCallbackHandler specifically tailored to handling the PasswordCallback. <br>
 *
 * @author Ray Krueger
 *
 * @see <a
 * href="http://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/callback/Callback.html">Callback</a>
 * @see <a
 * href="http://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/callback/PasswordCallback.html">
 * PasswordCallback</a>
 */
public class JaasPasswordCallbackHandler implements JaasAuthenticationCallbackHandler {
	// ~ Methods
	// ========================================================================================================

	/**
	 * If the callback passed to the 'handle' method is an instance of PasswordCallback,
	 * the JaasPasswordCallbackHandler will call,
	 * callback.setPassword(authentication.getCredentials().toString()).
	 *
	 * @param callback
	 * @param auth
	 *
	 * @throws IOException
	 * @throws UnsupportedCallbackException
	 */
	public void handle(Callback callback, Authentication auth) throws IOException,
			UnsupportedCallbackException {
		if (callback instanceof PasswordCallback) {
			PasswordCallback pc = (PasswordCallback) callback;
			pc.setPassword(auth.getCredentials().toString().toCharArray());
		}
	}
}
