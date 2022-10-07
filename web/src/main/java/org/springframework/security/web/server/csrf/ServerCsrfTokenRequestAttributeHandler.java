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

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.codec.multipart.FormFieldPart;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * An implementation of the {@link ServerCsrfTokenRequestHandler} interface that is
 * capable of making the {@link CsrfToken} available as an exchange attribute and
 * resolving the token value as either a form data value or header of the request.
 *
 * @author Steve Riesenberg
 * @since 5.8
 */
public class ServerCsrfTokenRequestAttributeHandler implements ServerCsrfTokenRequestHandler {

	private boolean isTokenFromMultipartDataEnabled;

	@Override
	public void handle(ServerWebExchange exchange, Mono<CsrfToken> csrfToken) {
		Assert.notNull(exchange, "exchange cannot be null");
		Assert.notNull(csrfToken, "csrfToken cannot be null");
		exchange.getAttributes().put(CsrfToken.class.getName(), csrfToken);
	}

	@Override
	public Mono<String> resolveCsrfTokenValue(ServerWebExchange exchange, CsrfToken csrfToken) {
		return ServerCsrfTokenRequestHandler.super.resolveCsrfTokenValue(exchange, csrfToken)
				.switchIfEmpty(tokenFromMultipartData(exchange, csrfToken));
	}

	/**
	 * Specifies if the {@code ServerCsrfTokenRequestResolver} should try to resolve the
	 * actual CSRF token from the body of multipart data requests.
	 * @param tokenFromMultipartDataEnabled true if should read from multipart form body,
	 * else false. Default is false
	 */
	public void setTokenFromMultipartDataEnabled(boolean tokenFromMultipartDataEnabled) {
		this.isTokenFromMultipartDataEnabled = tokenFromMultipartDataEnabled;
	}

	private Mono<String> tokenFromMultipartData(ServerWebExchange exchange, CsrfToken expected) {
		if (!this.isTokenFromMultipartDataEnabled) {
			return Mono.empty();
		}
		ServerHttpRequest request = exchange.getRequest();
		HttpHeaders headers = request.getHeaders();
		MediaType contentType = headers.getContentType();
		if (!MediaType.MULTIPART_FORM_DATA.isCompatibleWith(contentType)) {
			return Mono.empty();
		}
		return exchange.getMultipartData().map((d) -> d.getFirst(expected.getParameterName())).cast(FormFieldPart.class)
				.map(FormFieldPart::value);
	}

}
