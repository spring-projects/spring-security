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

package org.springframework.security.oauth2.client.web.reactive.result.method.annotation;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Optional;

/**
 * @author Rob Winch
 * @since 5.1
 */
class OAuth2AuthorizedClientResolver {

	private static final AnonymousAuthenticationToken ANONYMOUS_USER_TOKEN = new AnonymousAuthenticationToken("anonymous", "anonymousUser",
			AuthorityUtils.createAuthorityList("ROLE_USER"));

	private final ReactiveClientRegistrationRepository clientRegistrationRepository;

	private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

	private ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient = new WebClientReactiveClientCredentialsTokenResponseClient();

	private boolean defaultOAuth2AuthorizedClient;

	private String defaultClientRegistrationId;

	OAuth2AuthorizedClientResolver(
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientRepository = authorizedClientRepository;
	}

	/**
	 * If true, a default {@link OAuth2AuthorizedClient} can be discovered from the current Authentication. It is
	 * recommended to be cautious with this feature since all HTTP requests will receive the access token if it can be
	 * resolved from the current Authentication.
	 * @param defaultOAuth2AuthorizedClient true if a default {@link OAuth2AuthorizedClient} should be used, else false.
	 *                                      Default is false.
	 */
	public void setDefaultOAuth2AuthorizedClient(boolean defaultOAuth2AuthorizedClient) {
		this.defaultOAuth2AuthorizedClient = defaultOAuth2AuthorizedClient;
	}

	/**
	 * If set, will be used as the default {@link ClientRegistration#getRegistrationId()}. It is
	 * recommended to be cautious with this feature since all HTTP requests will receive the access token.
	 * @param clientRegistrationId the id to use
	 */
	public void setDefaultClientRegistrationId(String clientRegistrationId) {
		this.defaultClientRegistrationId = clientRegistrationId;
	}

	/**
	 * Sets the {@link ReactiveOAuth2AccessTokenResponseClient} to be used for getting an {@link OAuth2AuthorizedClient} for
	 * client_credentials grant.
	 * @param clientCredentialsTokenResponseClient the client to use
	 */
	public void setClientCredentialsTokenResponseClient(
			ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient) {
		Assert.notNull(clientCredentialsTokenResponseClient, "clientCredentialsTokenResponseClient cannot be null");
		this.clientCredentialsTokenResponseClient = clientCredentialsTokenResponseClient;
	}

	Mono<Request> createDefaultedRequest(String clientRegistrationId,
			Authentication authentication, ServerWebExchange exchange) {
		Mono<Authentication> defaultedAuthentication = Mono.justOrEmpty(authentication)
				.switchIfEmpty(currentAuthentication());

		Mono<String> defaultedRegistrationId = Mono.justOrEmpty(clientRegistrationId)
				.switchIfEmpty(Mono.justOrEmpty(this.defaultClientRegistrationId))
				.switchIfEmpty(clientRegistrationId(defaultedAuthentication))
				.switchIfEmpty(Mono.error(() -> new IllegalArgumentException("The clientRegistrationId could not be resolved. Please provide one")));

		Mono<Optional<ServerWebExchange>> defaultedExchange = Mono.justOrEmpty(exchange)
				.switchIfEmpty(currentServerWebExchange()).map(Optional::of)
				.defaultIfEmpty(Optional.empty());

		return Mono.zip(defaultedRegistrationId, defaultedAuthentication, defaultedExchange)
				.map(t3 -> new Request(t3.getT1(), t3.getT2(), t3.getT3().orElse(null)));
	}

	Mono<OAuth2AuthorizedClient> loadAuthorizedClient(Request request) {
		String clientRegistrationId = request.getClientRegistrationId();
		Authentication authentication = request.getAuthentication();
		ServerWebExchange exchange = request.getExchange();
		return this.authorizedClientRepository.loadAuthorizedClient(clientRegistrationId, authentication, exchange)
				.switchIfEmpty(authorizedClientNotLoaded(clientRegistrationId, authentication, exchange));
	}

	private Mono<OAuth2AuthorizedClient> authorizedClientNotLoaded(String clientRegistrationId, Authentication authentication, ServerWebExchange exchange) {
		return this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId)
			.switchIfEmpty(Mono.error(() -> new IllegalArgumentException("Client Registration with id " + clientRegistrationId + " was not found")))
			.flatMap(clientRegistration -> {
				if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(clientRegistration.getAuthorizationGrantType())) {
					return clientCredentials(clientRegistration, authentication, exchange);
				}
				return Mono.error(() -> new ClientAuthorizationRequiredException(clientRegistrationId));
			});
}

	private Mono<? extends OAuth2AuthorizedClient> clientCredentials(
			ClientRegistration clientRegistration, Authentication authentication, ServerWebExchange exchange) {
		OAuth2ClientCredentialsGrantRequest grantRequest = new OAuth2ClientCredentialsGrantRequest(clientRegistration);
		return this.clientCredentialsTokenResponseClient.getTokenResponse(grantRequest)
				.flatMap(tokenResponse -> clientCredentialsResponse(clientRegistration, authentication, exchange, tokenResponse));
	}

	private Mono<OAuth2AuthorizedClient> clientCredentialsResponse(ClientRegistration clientRegistration, Authentication authentication, ServerWebExchange exchange, OAuth2AccessTokenResponse tokenResponse) {
		OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
				clientRegistration, authentication.getName(), tokenResponse.getAccessToken());
		return this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, authentication, exchange)
				.thenReturn(authorizedClient);
	}

	/**
	 * Attempts to load the client registration id from the current {@link Authentication}
	 * @return
	 */
	private Mono<String> clientRegistrationId(Mono<Authentication> authentication) {
		return authentication
				.filter(t -> this.defaultOAuth2AuthorizedClient && t instanceof OAuth2AuthenticationToken)
				.cast(OAuth2AuthenticationToken.class)
				.map(OAuth2AuthenticationToken::getAuthorizedClientRegistrationId);
	}

	private Mono<Authentication> currentAuthentication() {
		return ReactiveSecurityContextHolder.getContext()
				.map(SecurityContext::getAuthentication)
				.defaultIfEmpty(ANONYMOUS_USER_TOKEN);
	}

	private Mono<ServerWebExchange> currentServerWebExchange() {
		return Mono.subscriberContext()
				.filter(c -> c.hasKey(ServerWebExchange.class))
				.map(c -> c.get(ServerWebExchange.class));
	}

	static class Request {
		private final String clientRegistrationId;
		private final Authentication authentication;
		private final ServerWebExchange exchange;

		Request(String clientRegistrationId, Authentication authentication,
				ServerWebExchange exchange) {
			this.clientRegistrationId = clientRegistrationId;
			this.authentication = authentication;
			this.exchange = exchange;
		}

		public String getClientRegistrationId() {
			return this.clientRegistrationId;
		}

		public Authentication getAuthentication() {
			return this.authentication;
		}

		public ServerWebExchange getExchange() {
			return this.exchange;
		}
	}
}
