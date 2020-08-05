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
 * Converts from a {@link ServerWebExchange} to an {@link Authentication} that can be
 * authenticated.
 *
 * @author Rob Winch
 * @since 5.1
 */
@SuppressWarnings("deprecation")
public class ServerHttpBasicAuthenticationConverter
		extends org.springframework.security.web.server.ServerHttpBasicAuthenticationConverter
		implements ServerAuthenticationConverter {

	@Override
	public Mono<Authentication> convert(ServerWebExchange exchange) {
		return apply(exchange);
	}

}
