/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.web;

import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.UriComponentsBuilder;

import reactor.core.publisher.Mono;

/**
 * This {@code WebFilter} initiates the authorization code grant or implicit grant flow
 * by redirecting the End-User's user-agent to the Authorization Server's Authorization Endpoint.
 *
 * <p>
 * It builds the OAuth 2.0 Authorization Request,
 * which is used as the redirect {@code URI} to the Authorization Endpoint.
 * The redirect {@code URI} will include the client identifier, requested scope(s), state,
 * response type, and a redirection URI which the authorization server will send the user-agent back to
 * once access is granted (or denied) by the End-User (Resource Owner).
 *
 * <p>
 * By default, this {@code Filter} responds to authorization requests
 * at the {@code URI} {@code /oauth2/authorization/{registrationId}}.
 * The {@code URI} template variable {@code {registrationId}} represents the
 * {@link ClientRegistration#getRegistrationId() registration identifier} of the client
 * that is used for initiating the OAuth 2.0 Authorization Request.
 *
 * <p>
 * <b>NOTE:</b> The default base {@code URI} {@code /oauth2/authorization} may be overridden
 * via it's constructor {@link #OAuth2AuthorizationRequestRedirectWebFilter(ReactiveClientRegistrationRepository, String)}.

 * @author Rob Winch
 * @since 5.1
 * @see OAuth2AuthorizationRequest
 * @see AuthorizationRequestRepository
 * @see ClientRegistration
 * @see ClientRegistrationRepository
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Request (Authorization Code)</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.2">Section 4.2 Implicit Grant</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.2.1">Section 4.2.1 Authorization Request (Implicit)</a>
 */
public class OAuth2AuthorizationRequestRedirectWebFilter implements WebFilter {
	/**
	 * The default base {@code URI} used for authorization requests.
	 */
	public static final String DEFAULT_AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization";
	private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
	private static final String AUTHORIZATION_REQUIRED_EXCEPTION_ATTR_NAME =
			ClientAuthorizationRequiredException.class.getName() + ".AUTHORIZATION_REQUIRED_EXCEPTION";
	private final ServerWebExchangeMatcher authorizationRequestMatcher;
	private final ReactiveClientRegistrationRepository clientRegistrationRepository;
	private final OAuth2AuthorizationRequestUriBuilder authorizationRequestUriBuilder = new OAuth2AuthorizationRequestUriBuilder();
	private final ServerRedirectStrategy authorizationRedirectStrategy = new DefaultServerRedirectStrategy();
	private final StringKeyGenerator stateGenerator = new Base64StringKeyGenerator(Base64.getUrlEncoder());
	private ReactiveAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
		new WebSessionOAuth2ReactiveAuthorizationRequestRepository();

	/**
	 * Constructs an {@code OAuth2AuthorizationRequestRedirectFilter} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 */
	public OAuth2AuthorizationRequestRedirectWebFilter(ReactiveClientRegistrationRepository clientRegistrationRepository) {
		this(clientRegistrationRepository, DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
	}

	/**
	 * Constructs an {@code OAuth2AuthorizationRequestRedirectFilter} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizationRequestBaseUri the base {@code URI} used for authorization requests
	 */
	public OAuth2AuthorizationRequestRedirectWebFilter(
		ReactiveClientRegistrationRepository clientRegistrationRepository, String authorizationRequestBaseUri) {

		Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.authorizationRequestMatcher = new PathPatternParserServerWebExchangeMatcher(
			authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	/**
	 * Sets the repository used for storing {@link OAuth2AuthorizationRequest}'s.
	 *
	 * @param authorizationRequestRepository the repository used for storing {@link OAuth2AuthorizationRequest}'s
	 */
	public final void setAuthorizationRequestRepository(ReactiveAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository) {
		Assert.notNull(authorizationRequestRepository, "authorizationRequestRepository cannot be null");
		this.authorizationRequestRepository = authorizationRequestRepository;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return this.authorizationRequestMatcher.matches(exchange)
			.filter(matchResult -> matchResult.isMatch())
			.switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
			.map(ServerWebExchangeMatcher.MatchResult::getVariables)
			.map(variables -> variables.get(REGISTRATION_ID_URI_VARIABLE_NAME))
			.cast(String.class)
			.flatMap(clientRegistrationId -> this.findByRegistrationId(exchange, clientRegistrationId))
			.flatMap(clientRegistration -> sendRedirectForAuthorization(exchange, clientRegistration));
	}

	private Mono<ClientRegistration> findByRegistrationId(ServerWebExchange exchange, String clientRegistration) {
		return this.clientRegistrationRepository.findByRegistrationId(clientRegistration)
			.switchIfEmpty(Mono.defer(() -> {
				exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);
				return exchange.getResponse().setComplete().then(Mono.empty());
			}));
	}

	private Mono<Void> sendRedirectForAuthorization(ServerWebExchange exchange,
												ClientRegistration clientRegistration) {
		return Mono.defer(() -> {
			String redirectUriStr = this
					.expandRedirectUri(exchange.getRequest(), clientRegistration);

			Map<String, Object> additionalParameters = new HashMap<>();
			additionalParameters.put(OAuth2ParameterNames.REGISTRATION_ID,
					clientRegistration.getRegistrationId());

			OAuth2AuthorizationRequest.Builder builder;
			if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
				builder = OAuth2AuthorizationRequest.authorizationCode();
			}
			else if (AuthorizationGrantType.IMPLICIT.equals(clientRegistration.getAuthorizationGrantType())) {
				builder = OAuth2AuthorizationRequest.implicit();
			}
			else {
				throw new IllegalArgumentException(
						"Invalid Authorization Grant Type (" + clientRegistration.getAuthorizationGrantType().getValue()
								+ ") for Client Registration with Id: " + clientRegistration.getRegistrationId());
			}
			OAuth2AuthorizationRequest authorizationRequest = builder
					.clientId(clientRegistration.getClientId())
					.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri())
					.redirectUri(redirectUriStr).scopes(clientRegistration.getScopes())
					.state(this.stateGenerator.generateKey())
					.additionalParameters(additionalParameters).build();

			Mono<Void> saveAuthorizationRequest = Mono.empty();
			if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationRequest.getGrantType())) {
				saveAuthorizationRequest = this.authorizationRequestRepository
						.saveAuthorizationRequest(authorizationRequest, exchange);
			}

			URI redirectUri = this.authorizationRequestUriBuilder.build(authorizationRequest);
			return saveAuthorizationRequest
					.then(this.authorizationRedirectStrategy.sendRedirect(exchange, redirectUri));
		});
	}

	private String expandRedirectUri(ServerHttpRequest request, ClientRegistration clientRegistration) {
		// Supported URI variables -> baseUrl, action, registrationId
		// Used in -> CommonOAuth2Provider.DEFAULT_REDIRECT_URL = "{baseUrl}/{action}/oauth2/code/{registrationId}"
		Map<String, String> uriVariables = new HashMap<>();
		uriVariables.put("registrationId", clientRegistration.getRegistrationId());

		String baseUrl = UriComponentsBuilder.fromHttpRequest(new ServerHttpRequestDecorator(request))
				.replacePath(request.getPath().contextPath().value())
				.build()
				.toUriString();
		uriVariables.put("baseUrl", baseUrl);

		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(clientRegistration.getAuthorizationGrantType())) {
			String loginAction = "login";
			uriVariables.put("action", loginAction);
		}

		return UriComponentsBuilder.fromUriString(clientRegistration.getRedirectUriTemplate())
			.buildAndExpand(uriVariables)
			.toUriString();
	}
}
