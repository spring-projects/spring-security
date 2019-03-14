/*
 * Copyright 2002-2018 the original author or authors.
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

import org.springframework.security.core.Authentication;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * A strategy used for converting from a {@link ServerWebExchange} to an {@link Authentication} used for
 * authenticating with a provided {@link org.springframework.security.authentication.ReactiveAuthenticationManager}.
 * If the result is {@link Mono#empty()}, then it signals that no authentication attempt should be made.
 *
 * @author Eric Deandrea
 * @since 5.1
 */
@FunctionalInterface
public interface ServerAuthenticationConverter {
	/**
	 * Converts a {@link ServerWebExchange} to an {@link Authentication}
	 * @param exchange The {@link ServerWebExchange}
	 * @return A {@link Mono} representing an {@link Authentication}
	 */
	Mono<Authentication> convert(ServerWebExchange exchange);
}
