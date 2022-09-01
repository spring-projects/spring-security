/*
 * Copyright 2002-2022 the original author or authors.
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

import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * A callback interface that is used to make the {@link CsrfToken} created by the
 * {@link ServerCsrfTokenRepository} available as an exchange attribute. Implementations
 * of this interface may choose to perform additional tasks or customize how the token is
 * made available to the application through exchange attributes.
 *
 * @author Steve Riesenberg
 * @since 5.8
 * @see ServerCsrfTokenRequestAttributeHandler
 */
@FunctionalInterface
public interface ServerCsrfTokenRequestHandler extends ServerCsrfTokenRequestResolver {

	/**
	 * Handles a request using a {@link CsrfToken}.
	 * @param exchange the {@code ServerWebExchange} with the request being handled
	 * @param csrfToken the {@code Mono<CsrfToken>} created by the
	 * {@link ServerCsrfTokenRepository}
	 */
	void handle(ServerWebExchange exchange, Mono<CsrfToken> csrfToken);

	@Override
	default Mono<String> resolveCsrfTokenValue(ServerWebExchange exchange, CsrfToken csrfToken) {
		Assert.notNull(exchange, "exchange cannot be null");
		Assert.notNull(csrfToken, "csrfToken cannot be null");
		return exchange.getFormData().flatMap((data) -> Mono.justOrEmpty(data.getFirst(csrfToken.getParameterName())))
				.switchIfEmpty(
						Mono.justOrEmpty(exchange.getRequest().getHeaders().getFirst(csrfToken.getHeaderName())));
	}

}
