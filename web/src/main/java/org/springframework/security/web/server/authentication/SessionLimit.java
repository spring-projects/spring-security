/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.web.server.authentication;

import java.util.function.Function;

import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;

/**
 * Represents the maximum number of sessions allowed. Use {@link #UNLIMITED} to indicate
 * that there is no limit.
 *
 * @author Marcus da Coregio
 * @since 6.3
 * @see ConcurrentSessionControlServerAuthenticationSuccessHandler
 */
public interface SessionLimit extends Function<Authentication, Mono<Integer>> {

	/**
	 * Represents unlimited sessions. This is just a shortcut to return
	 * {@link Mono#empty()} for any user.
	 */
	SessionLimit UNLIMITED = (authentication) -> Mono.empty();

	/**
	 * Creates a {@link SessionLimit} that always returns the given value for any user
	 * @param maxSessions the maximum number of sessions allowed
	 * @return a {@link SessionLimit} instance that returns the given value.
	 */
	static SessionLimit of(int maxSessions) {
		return (authentication) -> Mono.just(maxSessions);
	}

}
