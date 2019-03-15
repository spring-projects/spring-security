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
package org.springframework.security.web.server;

import java.util.Base64;
import java.util.function.Function;

import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * Converts from a {@link ServerWebExchange} to an {@link Authentication} that can be authenticated.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class ServerHttpBasicAuthenticationConverter implements Function<ServerWebExchange, Mono<Authentication>> {

	public static final String BASIC = "Basic ";

	@Override
	public Mono<Authentication> apply(ServerWebExchange exchange) {
		ServerHttpRequest request = exchange.getRequest();

		String authorization = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
		if(authorization == null || !authorization.toLowerCase().startsWith("basic ")) {
			return Mono.empty();
		}

		String credentials = authorization.length() <= BASIC.length() ?
			"" : authorization.substring(BASIC.length(), authorization.length());
		byte[] decodedCredentials = base64Decode(credentials);
		String decodedAuthz = new String(decodedCredentials);
		String[] userParts = decodedAuthz.split(":", 2);

		if(userParts.length != 2) {
			return Mono.empty();
		}

		String username = userParts[0];
		String password = userParts[1];

		return Mono.just(new UsernamePasswordAuthenticationToken(username, password));
	}

	private byte[] base64Decode(String value) {
		try {
			return Base64.getDecoder().decode(value);
		} catch(Exception e) {
			return new byte[0];
		}
	}
}
