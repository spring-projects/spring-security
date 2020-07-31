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

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;

/**
 * A reactive authorization manager which can determine if an {@link Authentication} has
 * access to a specific object.
 *
 * @param <T> the type of object that the authorization check is being done one.
 * @author Rob Winch
 * @since 5.0
 */
public interface ReactiveAuthorizationManager<T> {

	/**
	 * Determines if access is granted for a specific authentication and object.
	 * @param authentication the Authentication to check
	 * @param object the object to check
	 * @return an decision or empty Mono if no decision could be made.
	 */
	Mono<AuthorizationDecision> check(Mono<Authentication> authentication, T object);

	/**
	 * Determines if access should be granted for a specific authentication and object
	 * @param authentication the Authentication to check
	 * @param object the object to check
	 * @return an empty Mono if authorization is granted or a Mono error if access is
	 * denied
	 */
	default Mono<Void> verify(Mono<Authentication> authentication, T object) {
		return check(authentication, object).filter(AuthorizationDecision::isGranted)
				.switchIfEmpty(Mono.defer(() -> Mono.error(new AccessDeniedException("Access Denied"))))
				.flatMap((decision) -> Mono.empty());
	}

}
