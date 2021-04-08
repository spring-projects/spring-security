/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.authorization.method;

import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;

/**
 * Adapts an {@link AuthorizationManager} into an {@link AfterMethodAuthorizationManager}
 *
 * @param <T> the {@code T} object to authorize, typically a {@link MethodInvocation}
 * @author Josh Cummings
 * @since 5.5
 */
public final class AfterMethodAuthorizationManagerAdapter<T> implements AfterMethodAuthorizationManager<T> {

	private final AuthorizationManager<T> authorizationManager;

	/**
	 * Construct a {@link AfterMethodAuthorizationManagerAdapter} with the provided
	 * parameters
	 * @param authorizationManager the {@link AuthorizationManager} to adapt
	 */
	public AfterMethodAuthorizationManagerAdapter(AuthorizationManager<T> authorizationManager) {
		this.authorizationManager = authorizationManager;
	}

	/**
	 * Determine if access is granted for a specific authentication and {@code T} object.
	 *
	 * Note that the {@code returnedObject} parameter is ignored
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param object the {@code T} object to check, typically a {@link MethodInvocation}
	 * @param returnedObject the returned object from the method invocation, ignored in
	 * this implementation
	 * @return an {@link AuthorizationDecision} or null if no decision could be made
	 */
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, T object, Object returnedObject) {
		return this.authorizationManager.check(authentication, object);
	}

}
