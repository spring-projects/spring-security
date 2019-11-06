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

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * A {@link ServerAuthenticationEntryPoint} that sends a generic {@link HttpStatus} as a
 * response. Useful for JavaScript clients which cannot use Basic authentication since the
 * browser intercepts the response.
 *
 * @author Eric Deandrea
 * @since 5.1
 */
public class HttpStatusServerEntryPoint implements ServerAuthenticationEntryPoint {
	private final HttpStatus httpStatus;

	public HttpStatusServerEntryPoint(HttpStatus httpStatus) {
		Assert.notNull(httpStatus, "httpStatus cannot be null");
		this.httpStatus = httpStatus;
	}

	@Override
	public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException authException) {
		return Mono.fromRunnable(() -> exchange.getResponse().setStatusCode(this.httpStatus));
	}
}
