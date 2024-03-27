/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.web.server.authentication;

import java.util.List;

import reactor.core.publisher.Mono;

import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.web.AbstractBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;

/**
 * A strategy for resolving
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
 * Token</a>s from the {@link ServerWebExchange}.
 *
 * @author Rob Winch
 * @since 5.1
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-2" target="_blank">RFC 6750
 * Section 2: Authenticated Requests</a>
 */
public class ServerBearerTokenAuthenticationConverter
		extends AbstractBearerTokenAuthenticationConverter<ServerHttpRequest> implements ServerAuthenticationConverter {

	@Override
	public Mono<Authentication> convert(ServerWebExchange exchange) {
		// @formatter:off
		return Mono.fromCallable(() -> token(exchange.getRequest()))
				.map(this::convertBearerToken);
		// @formatter:on
	}

	@Override
	protected String resolveAuthorizationHeaderToken(ServerHttpRequest request) {
		String authorization = request.getHeaders().getFirst(this.bearerTokenHeaderName);
		return resolveFromAuthorizationHeader(authorization);
	}

	@Override
	protected List<String> resolveParameterTokens(ServerHttpRequest request) {
		return request.getQueryParams().get("access_token");
	}

	@Override
	protected HttpMethod getHttpMethod(ServerHttpRequest request) {
		return request.getMethod();
	}

}
