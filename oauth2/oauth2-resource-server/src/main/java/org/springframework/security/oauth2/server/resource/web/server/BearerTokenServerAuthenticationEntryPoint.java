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

package org.springframework.security.oauth2.server.resource.web.server;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An {@link AuthenticationEntryPoint} implementation used to commence authentication of protected resource requests
 * using {@link BearerTokenAuthenticationFilter}.
 * <p>
 * Uses information provided by {@link BearerTokenError} to set HTTP response status code and populate
 * {@code WWW-Authenticate} HTTP header.
 *
 * @author Rob Winch
 * @see BearerTokenError
 * @see <a href="https://tools.ietf.org/html/rfc6750#section-3" target="_blank">RFC 6750 Section 3: The WWW-Authenticate
 * Response Header Field</a>
 * @since 5.1
 */
public final class BearerTokenServerAuthenticationEntryPoint implements
		ServerAuthenticationEntryPoint {

	private String realmName;

	public void setRealmName(String realmName) {
		this.realmName = realmName;
	}

	@Override
	public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException authException) {
		return Mono.defer(() -> {
			HttpStatus status = getStatus(authException);

			Map<String, String> parameters = createParameters(authException);
			String wwwAuthenticate = computeWWWAuthenticateHeaderValue(parameters);
			ServerHttpResponse response = exchange.getResponse();
			response.getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
			response.setStatusCode(status);
			return response.setComplete();
		});
	}

	private Map<String, String> createParameters(AuthenticationException authException) {
		Map<String, String> parameters = new LinkedHashMap<>();
		if (this.realmName != null) {
			parameters.put("realm", this.realmName);
		}

		if (authException instanceof OAuth2AuthenticationException) {
			OAuth2Error error = ((OAuth2AuthenticationException) authException).getError();

			parameters.put("error", error.getErrorCode());

			if (StringUtils.hasText(error.getDescription())) {
				parameters.put("error_description", error.getDescription());
			}

			if (StringUtils.hasText(error.getUri())) {
				parameters.put("error_uri", error.getUri());
			}

			if (error instanceof BearerTokenError) {
				BearerTokenError bearerTokenError = (BearerTokenError) error;

				if (StringUtils.hasText(bearerTokenError.getScope())) {
					parameters.put("scope", bearerTokenError.getScope());
				}
			}
		}
		return parameters;
	}

	private HttpStatus getStatus(AuthenticationException authException) {
		if (authException instanceof OAuth2AuthenticationException) {
			OAuth2Error error = ((OAuth2AuthenticationException) authException).getError();
			if (error instanceof BearerTokenError) {
				return ((BearerTokenError) error).getHttpStatus();
			}
		}
		return HttpStatus.UNAUTHORIZED;
	}

	private static String computeWWWAuthenticateHeaderValue(Map<String, String> parameters) {
		StringBuilder wwwAuthenticate = new StringBuilder();
		wwwAuthenticate.append("Bearer");

		if (!parameters.isEmpty()) {
			wwwAuthenticate.append(" ");
			int i = 0;
			for (Map.Entry<String, String> entry : parameters.entrySet()) {
				wwwAuthenticate.append(entry.getKey()).append("=\"").append(entry.getValue()).append("\"");
				if (i != parameters.size() - 1) {
					wwwAuthenticate.append(", ");
				}
				i++;
			}
		}

		return wwwAuthenticate.toString();
	}
}
