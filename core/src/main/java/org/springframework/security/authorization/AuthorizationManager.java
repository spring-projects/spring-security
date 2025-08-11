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

package org.springframework.security.authorization;

import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;

/**
 * An Authorization manager which can determine if an {@link Authentication} has access to
 * a specific object.
 *
 * @param <T> the type of object that the authorization check is being done on.
 * @author Evgeniy Cheban
 */
@FunctionalInterface
public interface AuthorizationManager<T extends @Nullable Object> {

	/**
	 * Determines if access should be granted for a specific authentication and object.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param object the {@link T} object to check
	 * @throws AccessDeniedException if access is not granted
	 */
	default void verify(Supplier<Authentication> authentication, T object) {
		AuthorizationResult result = authorize(authentication, object);
		if (result != null && !result.isGranted()) {
			throw new AuthorizationDeniedException("Access Denied", result);
		}
	}

	/**
	 * Determines if access is granted for a specific authentication and object.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to
	 * authorize
	 * @param object the {@link T} object to authorize
	 * @return an {@link AuthorizationResult}
	 * @since 6.4
	 */
	@Nullable AuthorizationResult authorize(Supplier<Authentication> authentication, T object);

}
