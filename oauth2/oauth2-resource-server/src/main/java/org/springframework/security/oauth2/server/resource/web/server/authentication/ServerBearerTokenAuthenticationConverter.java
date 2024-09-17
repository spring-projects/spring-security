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

import static org.springframework.security.oauth2.server.resource.BearerTokenErrors.invalidRequest;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.function.Tuple2;
import reactor.util.function.Tuples;

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

	public static final String ACCESS_TOKEN_NAME = "access_token";
	public static final String MULTIPLE_BEARER_TOKENS_ERROR_MSG = "Found multiple bearer tokens in the request";
	private static final Pattern authorizationPattern = Pattern.compile("^Bearer (?<token>[a-zA-Z0-9-._~+/]+=*)$",
			Pattern.CASE_INSENSITIVE);

	private boolean allowUriQueryParameter = false;

	private boolean allowFormEncodedBodyParameter = false;

	private String bearerTokenHeaderName = HttpHeaders.AUTHORIZATION;

	@Override
	public Mono<Authentication> convert(ServerWebExchange exchange) {
		return Mono.defer(() -> token(exchange)).map(token -> {
			if (token.isEmpty()) {
				BearerTokenError error = invalidTokenError();
				throw new OAuth2AuthenticationException(error);
			}
			return new BearerTokenAuthenticationToken(token);
		});
	}

	private Mono<String> token(ServerWebExchange exchange) {
		final ServerHttpRequest request = exchange.getRequest();

		return Flux.merge(resolveFromAuthorizationHeader(request.getHeaders()).map(s -> Tuples.of(s, TokenSource.HEADER)),
						  resolveAccessTokenFromRequest(request).map(s -> Tuples.of(s, TokenSource.QUERY_PARAMETER)),
						  resolveAccessTokenFromBody(exchange).map(s -> Tuples.of(s, TokenSource.BODY_PARAMETER)))
				   .collectList()
				   .mapNotNull(tokenTuples -> {
					   switch (tokenTuples.size()) {
						   case 0:
							   return null;
						   case 1:
							   return getTokenIfSupported(tokenTuples.get(0), request);
						   default:
							   BearerTokenError error = invalidRequest(MULTIPLE_BEARER_TOKENS_ERROR_MSG);
							   throw new OAuth2AuthenticationException(error);
					   }
				   });
	}

	private static Mono<String> resolveAccessTokenFromRequest(ServerHttpRequest request) {
		List<String> parameterTokens = request.getQueryParams().get(ACCESS_TOKEN_NAME);
		if (CollectionUtils.isEmpty(parameterTokens)) {
			return Mono.empty();
		}
		if (parameterTokens.size() == 1) {
			return Mono.just(parameterTokens.get(0));
		}

		BearerTokenError error = invalidRequest(MULTIPLE_BEARER_TOKENS_ERROR_MSG);
		throw new OAuth2AuthenticationException(error);

	}

	private String getTokenIfSupported(Tuple2<String, TokenSource> tokenTuple, ServerHttpRequest request) {
		switch (tokenTuple.getT2()) {
			case HEADER:
				return tokenTuple.getT1();
			case QUERY_PARAMETER:
				return isParameterTokenSupportedForRequest(request) ? tokenTuple.getT1() : null;
			case BODY_PARAMETER:
				return isBodyParameterTokenSupportedForRequest(request) ? tokenTuple.getT1() : null;
			default:
				throw new IllegalArgumentException();
		}
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

	private Mono<String> resolveFromAuthorizationHeader(HttpHeaders headers) {
		String authorization = headers.getFirst(this.bearerTokenHeaderName);
		if (!StringUtils.startsWithIgnoreCase(authorization, "bearer")) {
			return Mono.empty();
		}
		Matcher matcher = authorizationPattern.matcher(authorization);
		if (!matcher.matches()) {
			BearerTokenError error = invalidTokenError();
			throw new OAuth2AuthenticationException(error);
		}
		return Mono.just(matcher.group("token"));
	}

	private static BearerTokenError invalidTokenError() {
		return BearerTokenErrors.invalidToken("Bearer token is malformed");
	}

	private Mono<String> resolveAccessTokenFromBody(ServerWebExchange exchange) {
		if (!allowFormEncodedBodyParameter) {
			return Mono.empty();
		}

		final ServerHttpRequest request = exchange.getRequest();

		if (request.getMethod() == HttpMethod.POST &&
				MediaType.APPLICATION_FORM_URLENCODED.equalsTypeAndSubtype(request.getHeaders().getContentType())) {

			return exchange.getFormData().mapNotNull(formData -> {
				if (formData.isEmpty()) {
					return null;
				}
				final List<String> tokens = formData.get(ACCESS_TOKEN_NAME);
				if (tokens == null) {
					return null;
				}
				if (tokens.size() > 1) {
					BearerTokenError error = invalidRequest(MULTIPLE_BEARER_TOKENS_ERROR_MSG);
					throw new OAuth2AuthenticationException(error);
				}
				return formData.getFirst(ACCESS_TOKEN_NAME);
			});
		}
		return Mono.empty();
	}

	private boolean isBodyParameterTokenSupportedForRequest(ServerHttpRequest request) {
		return this.allowFormEncodedBodyParameter && HttpMethod.POST == request.getMethod();
	}

	private boolean isParameterTokenSupportedForRequest(ServerHttpRequest request) {
		return this.allowUriQueryParameter && HttpMethod.GET.equals(request.getMethod());
	}

	private enum TokenSource {HEADER, QUERY_PARAMETER, BODY_PARAMETER}

}
