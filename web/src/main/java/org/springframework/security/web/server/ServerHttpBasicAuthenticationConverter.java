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

package org.springframework.security.web.server;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.function.Function;

import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

/**
 * Converts from a {@link ServerWebExchange} to an {@link Authentication} that can be
 * authenticated.
 *
 * @author Rob Winch
 * @since 5.0
 * @deprecated Use
 * {@link org.springframework.security.web.server.authentication.ServerHttpBasicAuthenticationConverter}
 * instead.
 */
@Deprecated
public class ServerHttpBasicAuthenticationConverter implements Function<ServerWebExchange, Mono<Authentication>> {

	public static final String BASIC = "Basic ";

	private Charset credentialsCharset = StandardCharsets.UTF_8;

	@Override
	@Deprecated
	public Mono<Authentication> apply(ServerWebExchange exchange) {
		ServerHttpRequest request = exchange.getRequest();
		String authorization = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
		if (!StringUtils.startsWithIgnoreCase(authorization, "basic ")) {
			return Mono.empty();
		}
		String credentials = (authorization.length() <= BASIC.length()) ? "" : authorization.substring(BASIC.length());
		String decoded = new String(base64Decode(credentials), this.credentialsCharset);
		String[] parts = decoded.split(":", 2);
		if (parts.length != 2) {
			return Mono.empty();
		}
		return Mono.just(UsernamePasswordAuthenticationToken.unauthenticated(parts[0], parts[1]));
	}

	private byte[] base64Decode(String value) {
		try {
			return Base64.getDecoder().decode(value);
		}
		catch (Exception ex) {
			return new byte[0];
		}
	}

	/**
	 * Sets the {@link Charset} used to decode the Base64-encoded bytes of the basic
	 * authentication credentials. The default is <code>UTF_8</code>.
	 * @param credentialsCharset the {@link Charset} used to decode the Base64-encoded
	 * bytes of the basic authentication credentials
	 * @since 5.7
	 */
	public final void setCredentialsCharset(Charset credentialsCharset) {
		Assert.notNull(credentialsCharset, "credentialsCharset cannot be null");
		this.credentialsCharset = credentialsCharset;
	}

}
