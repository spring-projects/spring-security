/*
 * Copyright 2002-2017 the original author or authors.
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

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;

/**
 * A {@link ReactiveAuthorizationManager} that determines if the current user is
 * authenticated.
 *
 * @param <T> The type of object authorization is being performed against. This does not
 * matter since the authorization decision does not use the object.
 * @author Rob Winch
 * @since 5.0
 */
public class AuthenticatedReactiveAuthorizationManager<T> implements ReactiveAuthorizationManager<T> {

	private AuthenticationTrustResolver authTrustResolver = new AuthenticationTrustResolverImpl();

	AuthenticatedReactiveAuthorizationManager() {
	}

	@Override
	public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, T object) {
		return authentication.filter(this::isNotAnonymous)
			.map(this::getAuthorizationDecision)
			.defaultIfEmpty(new AuthorizationDecision(false));
	}

	private AuthorizationDecision getAuthorizationDecision(Authentication authentication) {
		return new AuthorizationDecision(authentication.isAuthenticated());
	}

	/**
	 * Verify (via {@link AuthenticationTrustResolver}) that the given authentication is
	 * not anonymous.
	 * @param authentication to be checked
	 * @return <code>true</code> if not anonymous, otherwise <code>false</code>.
	 */
	private boolean isNotAnonymous(Authentication authentication) {
		return !this.authTrustResolver.isAnonymous(authentication);
	}

	/**
	 * Gets an instance of {@link AuthenticatedReactiveAuthorizationManager}
	 * @param <T>
	 * @return
	 */
	public static <T> AuthenticatedReactiveAuthorizationManager<T> authenticated() {
		return new AuthenticatedReactiveAuthorizationManager<>();
	}

}
