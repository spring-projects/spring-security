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

import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

/**
 * A {@link ReactiveAuthorizationManager} that determines if the current user is
 * authenticated.
 *
 * @author Rob Winch
 * @since 5.0
 * @param <T> The type of object authorization is being performed against. This does not
 * matter since the authorization decision does not use the object.
 */
public class AuthenticatedReactiveAuthorizationManager<T> implements ReactiveAuthorizationManager<T> {

	@Override
	public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, T object) {
		return authentication
			.map(a -> new AuthorizationDecision(a.isAuthenticated()))
			.defaultIfEmpty(new AuthorizationDecision(false));
	}

	/**
	 * Gets an instance of {@link AuthenticatedReactiveAuthorizationManager}
	 * @param <T>
	 * @return
	 */
	public static <T> AuthenticatedReactiveAuthorizationManager<T> authenticated() {
		return new AuthenticatedReactiveAuthorizationManager<>();
	}

	private AuthenticatedReactiveAuthorizationManager() {}
}
