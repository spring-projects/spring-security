/*
 * Copyright 2002-2020 the original author or authors.
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

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;

/**
 * An {@link AuthorizationManager} that determines if the current user is authenticated.
 *
 * @param <T> the type of object authorization is being performed against. This does not.
 * @author Evgeniy Cheban
 * @since 5.5
 */
public final class AuthenticatedAuthorizationManager<T> implements AuthorizationManager<T> {

	private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	/**
	 * Creates an instance of {@link AuthenticatedAuthorizationManager}.
	 * @param <T> the type of object being authorized
	 * @return the new instance
	 */
	public static <T> AuthenticatedAuthorizationManager<T> authenticated() {
		return new AuthenticatedAuthorizationManager<>();
	}

	/**
	 * Determines if the current user is authorized by evaluating if the
	 * {@link Authentication} is not anonymous and authenticated.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param object the {@link T} object to check
	 * @return an {@link AuthorizationDecision}
	 */
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, T object) {
		boolean granted = isGranted(authentication.get());
		return new AuthorizationDecision(granted);
	}

	private boolean isGranted(Authentication authentication) {
		return authentication != null && isNotAnonymous(authentication) && authentication.isAuthenticated();
	}

	private boolean isNotAnonymous(Authentication authentication) {
		return !this.trustResolver.isAnonymous(authentication);
	}

}
