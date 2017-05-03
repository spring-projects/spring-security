/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.springframework.security.authorization;

import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class AuthenticatedAuthorizationManager<T> implements ReactiveAuthorizationManager<T> {

	@Override
	public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, T object) {
		return authentication
			.map(a -> new AuthorizationDecision(a.isAuthenticated()))
			.defaultIfEmpty(new AuthorizationDecision(false));
	}

	public static <T> AuthenticatedAuthorizationManager<T> authenticated() {
		return new AuthenticatedAuthorizationManager<>();
	}

	private AuthenticatedAuthorizationManager() {}
}
