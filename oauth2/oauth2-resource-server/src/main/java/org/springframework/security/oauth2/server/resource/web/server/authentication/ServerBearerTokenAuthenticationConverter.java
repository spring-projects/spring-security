/*
 * Copyright 2002-2025 the original author or authors.
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.CollectionUtils;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
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
public class ServerBearerTokenAuthenticationConverter implements ServerAuthenticationConverter {

	private static final String ACCESS_TOKEN_PARAMETER_NAME = "access_token";

	private static final Pattern authorizationPattern = Pattern.compile("^Bearer (?<token>[a-zA-Z0-9-._~+/]+=*)$",
			Pattern.CASE_INSENSITIVE);

	private boolean allowFormEncodedBodyParameter = false;

	private boolean allowUriQueryParameter = false;

	private String bearerTokenHeaderName = HttpHeaders.AUTHORIZATION;

	@Override
	public Mono<Authentication> convert(ServerWebExchange exchange) {
		return Mono.defer(() -> {
			ServerHttpRequest request = exchange.getRequest();
			// @formatter:off
			return Flux.merge(resolveFromAuthorizationHeader(request.getHeaders()),
						resolveAccessTokenFromQueryString(request),
						resolveAccessTokenFromBody(exchange))
				.collectList()
				.flatMap(ServerBearerTokenAuthenticationConverter::resolveToken)
				.map(BearerTokenAuthenticationToken::new);
			// @formatter:on
		});
	}

	private static Mono<String> resolveToken(List<String> accessTokens) {
		if (CollectionUtils.isEmpty(accessTokens)) {
			return Mono.empty();
		}

		if (accessTokens.size() > 1) {
			BearerTokenError error = BearerTokenErrors.invalidRequest("Found multiple bearer tokens in the request");
			return Mono.error(new OAuth2AuthenticationException(error));
		}

		String accessToken = accessTokens.get(0);
		if (!StringUtils.hasText(accessToken)) {
			BearerTokenError error = BearerTokenErrors
				.invalidRequest("The requested token parameter is an empty string");
			return Mono.error(new OAuth2AuthenticationException(error));
		}

		return Mono.just(accessToken);
	}

	private Mono<String> resolveFromAuthorizationHeader(HttpHeaders headers) {
		String authorization = headers.getFirst(this.bearerTokenHeaderName);
		if (!StringUtils.startsWithIgnoreCase(authorization, "bearer")) {
			return Mono.empty();
		}

		Matcher matcher = authorizationPattern.matcher(authorization);
		if (!matcher.matches()) {
			BearerTokenError error = BearerTokenErrors.invalidToken("Bearer token is malformed");
			throw new OAuth2AuthenticationException(error);
		}

		return Mono.just(matcher.group("token"));
	}

	private Flux<String> resolveAccessTokenFromQueryString(ServerHttpRequest request) {
		if (!this.allowUriQueryParameter || !HttpMethod.GET.equals(request.getMethod())) {
			return Flux.empty();
		}

		return resolveTokens(request.getQueryParams());
	}

	private Flux<String> resolveAccessTokenFromBody(ServerWebExchange exchange) {
		ServerHttpRequest request = exchange.getRequest();
		if (!this.allowFormEncodedBodyParameter
				|| !MediaType.APPLICATION_FORM_URLENCODED.equals(request.getHeaders().getContentType())
				|| !HttpMethod.POST.equals(request.getMethod())) {
			return Flux.empty();
		}

		return exchange.getFormData().flatMapMany(ServerBearerTokenAuthenticationConverter::resolveTokens);
	}

	private static Flux<String> resolveTokens(MultiValueMap<String, String> parameters) {
		List<String> accessTokens = parameters.get(ACCESS_TOKEN_PARAMETER_NAME);
		return CollectionUtils.isEmpty(accessTokens) ? Flux.empty() : Flux.fromIterable(accessTokens);
	}

	/**
	 * Set if transport of access token using URI query parameter is supported. Defaults
	 * to {@code false}.
	 *
	 * The spec recommends against using this mechanism for sending bearer tokens, and
	 * even goes as far as stating that it was only included for completeness.
	 * @param allowUriQueryParameter if the URI query parameter is supported
	 */
	public void setAllowUriQueryParameter(boolean allowUriQueryParameter) {
		this.allowUriQueryParameter = allowUriQueryParameter;
	}

	/**
	 * Set this value to configure what header is checked when resolving a Bearer Token.
	 * This value is defaulted to {@link HttpHeaders#AUTHORIZATION}.
	 *
	 * This allows other headers to be used as the Bearer Token source such as
	 * {@link HttpHeaders#PROXY_AUTHORIZATION}
	 * @param bearerTokenHeaderName the header to check when retrieving the Bearer Token.
	 * @since 5.4
	 */
	public void setBearerTokenHeaderName(String bearerTokenHeaderName) {
		this.bearerTokenHeaderName = bearerTokenHeaderName;
	}

	/**
	 * Set if transport of access token using form-encoded body parameter is supported.
	 * Defaults to {@code false}.
	 * @param allowFormEncodedBodyParameter if the form-encoded body parameter is
	 * supported
	 * @since 6.5
	 */
	public void setAllowFormEncodedBodyParameter(boolean allowFormEncodedBodyParameter) {
		this.allowFormEncodedBodyParameter = allowFormEncodedBodyParameter;
	}

}
