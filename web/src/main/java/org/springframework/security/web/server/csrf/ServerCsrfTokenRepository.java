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
package org.springframework.security.web.server.csrf;

import reactor.core.publisher.Mono;

import org.springframework.web.server.ServerWebExchange;

/**
 * An API to allow changing the method in which the expected {@link CsrfToken} is
 * associated to the {@link ServerWebExchange}. For example, it may be stored in
 * {@link org.springframework.web.server.WebSession}.
 *
 * @author Rob Winch
 * @since 5.0
 * @see WebSessionServerCsrfTokenRepository
 *
 */
public interface ServerCsrfTokenRepository {

	/**
	 * Generates a {@link CsrfToken}
	 * @param exchange the {@link ServerWebExchange} to use
	 * @return the {@link CsrfToken} that was generated. Cannot be null.
	 */
	Mono<CsrfToken> generateToken(ServerWebExchange exchange);

	/**
	 * Saves the {@link CsrfToken} using the {@link ServerWebExchange}. If the
	 * {@link CsrfToken} is null, it is the same as deleting it.
	 * @param exchange the {@link ServerWebExchange} to use
	 * @param token the {@link CsrfToken} to save or null to delete
	 */
	Mono<Void> saveToken(ServerWebExchange exchange, CsrfToken token);

	/**
	 * Loads the expected {@link CsrfToken} from the {@link ServerWebExchange}
	 * @param exchange the {@link ServerWebExchange} to use
	 * @return the {@link CsrfToken} or null if none exists
	 */
	Mono<CsrfToken> loadToken(ServerWebExchange exchange);

}
