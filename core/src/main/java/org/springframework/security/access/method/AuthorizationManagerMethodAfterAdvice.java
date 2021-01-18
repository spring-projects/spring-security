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

package org.springframework.security.access.method;

import java.util.function.Supplier;

import org.springframework.aop.MethodMatcher;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationMethodAfterAdvice} which can determine if an
 * {@link Authentication} has access to the {@link T} object using an
 * {@link AuthorizationManager} if a {@link MethodMatcher} matches.
 *
 * @param <T> the type of object that the authorization check is being done one.
 * @author Evgeniy Cheban
 * @since 5.5
 */
public final class AuthorizationManagerMethodAfterAdvice<T> implements AuthorizationMethodAfterAdvice<T> {

	private final MethodMatcher methodMatcher;

	private final AuthorizationManager<T> authorizationManager;

	/**
	 * Creates an instance.
	 * @param methodMatcher the {@link MethodMatcher} to use
	 * @param authorizationManager the {@link AuthorizationManager} to use
	 */
	public AuthorizationManagerMethodAfterAdvice(MethodMatcher methodMatcher,
			AuthorizationManager<T> authorizationManager) {
		Assert.notNull(methodMatcher, "methodMatcher cannot be null");
		Assert.notNull(authorizationManager, "authorizationManager cannot be null");
		this.methodMatcher = methodMatcher;
		this.authorizationManager = authorizationManager;
	}

	/**
	 * Determines if an {@link Authentication} has access to the {@link T} object using
	 * the {@link AuthorizationManager}.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param object the {@link T} object to check
	 * @throws AccessDeniedException if access is not granted
	 */
	@Override
	public Object after(Supplier<Authentication> authentication, T object, Object returnedObject) {
		this.authorizationManager.verify(authentication, object);
		return returnedObject;
	}

	@Override
	public MethodMatcher getMethodMatcher() {
		return this.methodMatcher;
	}

}
