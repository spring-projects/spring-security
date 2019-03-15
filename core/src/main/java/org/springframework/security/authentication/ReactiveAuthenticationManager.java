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
package org.springframework.security.authentication;

import org.springframework.security.core.Authentication;

import reactor.core.publisher.Mono;

/**
 * Determines if the provided {@link Authentication} can be authenticated.
 *
 * @author Rob Winch
 * @since 5.0
 */
@FunctionalInterface
public interface ReactiveAuthenticationManager {

	/**
	 * Attempts to authenticate the provided {@link Authentication}
	 *
	 * @param authentication the {@link Authentication} to test
	 * @return if authentication is successful an {@link Authentication} is returned. If
	 * authentication cannot be determined, an empty Mono is returned. If authentication
	 * fails, a Mono error is returned.
	 */
	Mono<Authentication> authenticate(Authentication authentication);
}
