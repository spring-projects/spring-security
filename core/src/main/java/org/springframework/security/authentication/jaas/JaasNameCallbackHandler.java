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

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * The most basic Callbacks to be handled when using a LoginContext from JAAS, are the
 * NameCallback and PasswordCallback. Spring Security provides the JaasNameCallbackHandler
 * specifically tailored to handling the NameCallback. <br>
 *
 * @author Ray Krueger
 * @see <a href=
 * "https://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/callback/Callback.html">Callback</a>
 * @see <a href=
 * "https://java.sun.com/j2se/1.4.2/docs/api/javax/security/auth/callback/NameCallback.html">NameCallback</a>
 */
public class JaasNameCallbackHandler implements JaasAuthenticationCallbackHandler {

	/**
	 * If the callback passed to the 'handle' method is an instance of NameCallback, the
	 * JaasNameCallbackHandler will call,
	 * callback.setName(authentication.getPrincipal().toString()).
	 * @param callback
	 * @param authentication
	 *
	 */
	@Override
	public void handle(Callback callback, Authentication authentication) {
		if (callback instanceof NameCallback) {
			((NameCallback) callback).setName(getUserName(authentication));
		}
	}

	private String getUserName(Authentication authentication) {
		Object principal = authentication.getPrincipal();
		if (principal instanceof UserDetails) {
			return ((UserDetails) principal).getUsername();
		}
		return principal.toString();
	}

}
