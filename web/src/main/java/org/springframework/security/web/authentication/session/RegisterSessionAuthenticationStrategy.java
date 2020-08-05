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
package org.springframework.security.web.authentication.session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.util.Assert;

/**
 * Strategy used to register a user with the {@link SessionRegistry} after successful
 * {@link Authentication}.
 *
 * <p>
 * {@link RegisterSessionAuthenticationStrategy} is typically used in combination with
 * {@link CompositeSessionAuthenticationStrategy} and
 * {@link ConcurrentSessionControlAuthenticationStrategy}, but can be used on its own if
 * tracking of sessions is desired but no need to control concurrency.
 *
 * <p>
 * NOTE: When using a {@link SessionRegistry} it is important that all sessions (including
 * timed out sessions) are removed. This is typically done by adding
 * {@link HttpSessionEventPublisher}.
 *
 * @see CompositeSessionAuthenticationStrategy
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.2
 */
public class RegisterSessionAuthenticationStrategy implements SessionAuthenticationStrategy {

	private final SessionRegistry sessionRegistry;

	/**
	 * @param sessionRegistry the session registry which should be updated when the
	 * authenticated session is changed.
	 */
	public RegisterSessionAuthenticationStrategy(SessionRegistry sessionRegistry) {
		Assert.notNull(sessionRegistry, "The sessionRegistry cannot be null");
		this.sessionRegistry = sessionRegistry;
	}

	/**
	 * In addition to the steps from the superclass, the sessionRegistry will be updated
	 * with the new session information.
	 */
	public void onAuthentication(Authentication authentication, HttpServletRequest request,
			HttpServletResponse response) {
		sessionRegistry.registerNewSession(request.getSession().getId(), authentication.getPrincipal());
	}

}
