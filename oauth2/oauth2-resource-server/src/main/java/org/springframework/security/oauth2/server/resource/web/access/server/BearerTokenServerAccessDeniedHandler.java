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

package org.springframework.security.oauth2.server.resource.web.access.server;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Translates any {@link AccessDeniedException} into an HTTP response in accordance with
 * <a href="https://tools.ietf.org/html/rfc6750#section-3" target="_blank">RFC 6750 Section 3: The WWW-Authenticate</a>.
 *
 * So long as the class can prove that the request has a valid OAuth 2.0 {@link Authentication}, then will return an
 * <a href="https://tools.ietf.org/html/rfc6750#section-3.1" target="_blank">insufficient scope error</a>; otherwise,
 * it will simply indicate the scheme (Bearer) and any configured realm.
 *
 * @author Josh Cummings
 * @since 5.1
 *
 */
public class BearerTokenServerAccessDeniedHandler implements ServerAccessDeniedHandler {
	private static final Collection<String> WELL_KNOWN_SCOPE_ATTRIBUTE_NAMES =
			Arrays.asList("scope", "scp");

	private String realmName;

	@Override
	public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {

		Map<String, String> parameters = new LinkedHashMap<>();

		if (this.realmName != null) {
			parameters.put("realm", this.realmName);
		}

		return exchange.getPrincipal()
				.filter(AbstractOAuth2TokenAuthenticationToken.class::isInstance)
				.map(token -> errorMessageParameters(parameters))
				.switchIfEmpty(Mono.just(parameters))
				.flatMap(params -> respond(exchange, params));
	}

	/**
	 * Set the default realm name to use in the bearer token error response
	 *
	 * @param realmName
	 */
	public final void setRealmName(String realmName) {
		this.realmName = realmName;
	}

	private static Map<String, String> errorMessageParameters(Map<String, String> parameters) {
		parameters.put("error", BearerTokenErrorCodes.INSUFFICIENT_SCOPE);
		parameters.put("error_description", "The request requires higher privileges than provided by the access token.");
		parameters.put("error_uri", "https://tools.ietf.org/html/rfc6750#section-3.1");

		return parameters;
	}

	private static Mono<Void> respond(ServerWebExchange exchange, Map<String, String> parameters) {
		String wwwAuthenticate = computeWWWAuthenticateHeaderValue(parameters);
		exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
		exchange.getResponse().getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
		return exchange.getResponse().setComplete();
	}

	private static String computeWWWAuthenticateHeaderValue(Map<String, String> parameters) {
		String wwwAuthenticate = "Bearer";
		if (!parameters.isEmpty()) {
			wwwAuthenticate += parameters.entrySet().stream()
					.map(attribute -> attribute.getKey() + "=\"" + attribute.getValue() + "\"")
					.collect(Collectors.joining(", ", " ", ""));
		}

		return wwwAuthenticate;
	}
}
