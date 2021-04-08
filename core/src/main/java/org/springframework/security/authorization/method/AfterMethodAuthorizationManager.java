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

import org.springframework.lang.Nullable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;

/**
 * An Authorization manager which can determine if an {@link Authentication} has access to
 * a specific object and associated return object. Intended for use specifically to
 * evaluate the returning state of a method invocation.
 *
 * @param <T> the type of object that the authorization check is being done one.
 * @author Josh Cummings
 * @author Evgeniy Cheban
 * @since 5.5
 */
public interface AfterMethodAuthorizationManager<T> {

	/**
	 * Determine if access should be granted for a specific authentication, object and
	 * returnedObject.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param object the {@code T} object to check, typically a {@link MethodInvocation}
	 * @param returnedObject the returnedObject from the method invocation to check
	 * @throws AccessDeniedException if access is not granted
	 */
	default void verify(Supplier<Authentication> authentication, T object, Object returnedObject) {
		AuthorizationDecision decision = check(authentication, object, returnedObject);
		if (decision != null && !decision.isGranted()) {
			throw new AccessDeniedException("Access Denied");
		}
	}

	/**
	 * Determine if access is granted for a specific authentication, object, and
	 * returnedObject.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param object the {@code T} object to check, typically a {@link MethodInvocation}
	 * @param returnedObject the returned object from the method invocation to check
	 * @return an {@link AuthorizationDecision} or null if no decision could be made
	 */
	@Nullable
	AuthorizationDecision check(Supplier<Authentication> authentication, T object, Object returnedObject);

}
