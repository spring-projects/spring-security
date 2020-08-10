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
package org.springframework.security.web.server.authentication;

import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * Prompts a user for HTTP Basic authentication.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class HttpBasicServerAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

	private static final String WWW_AUTHENTICATE = "WWW-Authenticate";

	private static final String DEFAULT_REALM = "Realm";

	private static String WWW_AUTHENTICATE_FORMAT = "Basic realm=\"%s\"";

	private String headerValue = createHeaderValue(DEFAULT_REALM);

	@Override
	public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException e) {
		return Mono.fromRunnable(() -> {
			ServerHttpResponse response = exchange.getResponse();
			response.setStatusCode(HttpStatus.UNAUTHORIZED);
			response.getHeaders().set(WWW_AUTHENTICATE, this.headerValue);
		});
	}

	/**
	 * Sets the realm to be used
	 * @param realm the realm. Default is "Realm"
	 */
	public void setRealm(String realm) {
		this.headerValue = createHeaderValue(realm);
	}

	private static String createHeaderValue(String realm) {
		Assert.notNull(realm, "realm cannot be null");
		return String.format(WWW_AUTHENTICATE_FORMAT, realm);
	}

}
