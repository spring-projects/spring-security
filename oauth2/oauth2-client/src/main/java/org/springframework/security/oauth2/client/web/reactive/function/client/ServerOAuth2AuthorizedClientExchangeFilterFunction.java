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

package org.springframework.security.oauth2.client.web.reactive.function.client;

import com.sun.security.ntlm.Server;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
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
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import static org.springframework.security.oauth2.core.web.reactive.function.OAuth2BodyExtractors.oauth2AccessTokenResponse;

/**
 * Provides an easy mechanism for using an {@link OAuth2AuthorizedClient} to make OAuth2 requests by including the
 * token as a Bearer Token.
 *
 * @author Rob Winch
 * @since 5.1
 */
public final class ServerOAuth2AuthorizedClientExchangeFilterFunction implements ExchangeFilterFunction {
	/**
	 * The request attribute name used to locate the {@link OAuth2AuthorizedClient}.
	 */
	private static final String OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME = OAuth2AuthorizedClient.class.getName();

	/**
	 * The client request attribute name used to locate the {@link ClientRegistration#getRegistrationId()}
	 */
	private static final String CLIENT_REGISTRATION_ID_ATTR_NAME = OAuth2AuthorizedClient.class.getName().concat(".CLIENT_REGISTRATION_ID");

	/**
	 * The request attribute name used to locate the {@link org.springframework.web.server.ServerWebExchange}.
	 */
	private static final String SERVER_WEB_EXCHANGE_ATTR_NAME = ServerWebExchange.class.getName();

	private static final AnonymousAuthenticationToken ANONYMOUS_USER_TOKEN = new AnonymousAuthenticationToken("anonymous", "anonymousUser",
			AuthorityUtils.createAuthorityList("ROLE_USER"));

	private Clock clock = Clock.systemUTC();

	private Duration accessTokenExpiresSkew = Duration.ofMinutes(1);

	private boolean defaultOAuth2AuthorizedClient;

	private ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient =
			new WebClientReactiveClientCredentialsTokenResponseClient();

	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

	public ServerOAuth2AuthorizedClientExchangeFilterFunction() {}

	public ServerOAuth2AuthorizedClientExchangeFilterFunction(ReactiveClientRegistrationRepository clientRegistrationRepository, ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientRepository = authorizedClientRepository;
	}

	/**
	 * Modifies the {@link ClientRequest#attributes()} to include the {@link OAuth2AuthorizedClient} to be used for
	 * providing the Bearer Token. Example usage:
	 *
	 * <pre>
	 * WebClient webClient = WebClient.builder()
	 *    .filter(new OAuth2AuthorizedClientExchangeFilterFunction(authorizedClientRepository))
	 *    .build();
	 * Mono<String> response = webClient
	 *    .get()
	 *    .uri(uri)
	 *    .attributes(oauth2AuthorizedClient(authorizedClient))
	 *    // ...
	 *    .retrieve()
	 *    .bodyToMono(String.class);
	 * </pre>
	 *
	 * An attempt to automatically refresh the token will be made if all of the following
	 * are true:
	 *
	 * <ul>
	 * <li>The ReactiveOAuth2AuthorizedClientService on the
	 * {@link ServerOAuth2AuthorizedClientExchangeFilterFunction} is not null</li>
	 * <li>A refresh token is present on the OAuth2AuthorizedClient</li>
	 * <li>The access token will be expired in
	 * {@link #setAccessTokenExpiresSkew(Duration)}</li>
	 * <li>The {@link ReactiveSecurityContextHolder} will be used to attempt to save
	 * the token. If it is empty, then the principal name on the OAuth2AuthorizedClient
	 * will be used to create an Authentication for saving.</li>
	 * </ul>
	 *
	 * @param authorizedClient the {@link OAuth2AuthorizedClient} to use.
	 * @return the {@link Consumer} to populate the
	 */
	public static Consumer<Map<String, Object>> oauth2AuthorizedClient(OAuth2AuthorizedClient authorizedClient) {
		return attributes -> attributes.put(OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME, authorizedClient);
	}


	/**
	 * Modifies the {@link ClientRequest#attributes()} to include the {@link OAuth2AuthorizedClient} to be used for
	 * providing the Bearer Token. Example usage:
	 *
	 * <pre>
	 * WebClient webClient = WebClient.builder()
	 *    .filter(new OAuth2AuthorizedClientExchangeFilterFunction(authorizedClientRepository))
	 *    .build();
	 * Mono<String> response = webClient
	 *    .get()
	 *    .uri(uri)
	 *    .attributes(serverWebExchange(serverWebExchange))
	 *    // ...
	 *    .retrieve()
	 *    .bodyToMono(String.class);
	 * </pre>
	 * @param serverWebExchange the {@link ServerWebExchange} to use
	 * @return the {@link Consumer} to populate the client request attributes
	 */
	public static Consumer<Map<String, Object>> serverWebExchange(ServerWebExchange serverWebExchange) {
		return attributes -> attributes.put(SERVER_WEB_EXCHANGE_ATTR_NAME, serverWebExchange);
	}

	/**
	 * Modifies the {@link ClientRequest#attributes()} to include the {@link ClientRegistration#getRegistrationId()} to
	 * be used to look up the {@link OAuth2AuthorizedClient}.
	 *
	 * @param clientRegistrationId the {@link ClientRegistration#getRegistrationId()} to
	 * be used to look up the {@link OAuth2AuthorizedClient}.
	 * @return the {@link Consumer} to populate the attributes
	 */
	public static Consumer<Map<String, Object>> clientRegistrationId(String clientRegistrationId) {
		return attributes -> attributes.put(CLIENT_REGISTRATION_ID_ATTR_NAME, clientRegistrationId);
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
	 * Sets the {@link ReactiveOAuth2AccessTokenResponseClient} to be used for getting an {@link OAuth2AuthorizedClient} for
	 * client_credentials grant.
	 * @param clientCredentialsTokenResponseClient the client to use
	 */
	public void setClientCredentialsTokenResponseClient(
			ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient) {
		Assert.notNull(clientCredentialsTokenResponseClient, "clientCredentialsTokenResponseClient cannot be null");
		this.clientCredentialsTokenResponseClient = clientCredentialsTokenResponseClient;
	}

	/**
	 * An access token will be considered expired by comparing its expiration to now +
	 * this skewed Duration. The default is 1 minute.
	 * @param accessTokenExpiresSkew the Duration to use.
	 */
	public void setAccessTokenExpiresSkew(Duration accessTokenExpiresSkew) {
		Assert.notNull(accessTokenExpiresSkew, "accessTokenExpiresSkew cannot be null");
		this.accessTokenExpiresSkew = accessTokenExpiresSkew;
	}

	@Override
	public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
		return authorizedClient(request)
				.flatMap(authorizedClient -> refreshIfNecessary(next, authorizedClient, request))
				.map(authorizedClient -> bearer(request, authorizedClient))
				.flatMap(next::exchange)
				.switchIfEmpty(next.exchange(request));
	}

	private Mono<ServerWebExchange> serverWebExchange(ClientRequest request) {
		ServerWebExchange exchange = (ServerWebExchange) request.attributes().get(SERVER_WEB_EXCHANGE_ATTR_NAME);
		return Mono.justOrEmpty(exchange)
				.switchIfEmpty(serverWebExchange());
	}

	private Mono<ServerWebExchange> serverWebExchange() {
		return Mono.subscriberContext()
			.filter(c -> c.hasKey(ServerWebExchange.class))
			.map(c -> c.get(ServerWebExchange.class));
	}

	private Mono<OAuth2AuthorizedClient> authorizedClient(ClientRequest request) {
		Optional<OAuth2AuthorizedClient> attribute = request.attribute(OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME)
				.map(OAuth2AuthorizedClient.class::cast);
		return Mono.justOrEmpty(attribute)
				.switchIfEmpty(findAuthorizedClientByRegistrationId(request));
	}

	private Mono<OAuth2AuthorizedClient> findAuthorizedClientByRegistrationId(ClientRequest request) {
		if (this.authorizedClientRepository == null) {
			return Mono.empty();
		}

		return currentAuthentication()
			.flatMap(principal -> clientRegistrationId(request, principal)
					.flatMap(clientRegistrationId -> serverWebExchange(request).flatMap(exchange -> loadAuthorizedClient(clientRegistrationId, exchange, principal)))
			);
	}

	private Mono<String> clientRegistrationId(ClientRequest request, Authentication authentication) {
		return Mono.justOrEmpty(request.attributes().get(CLIENT_REGISTRATION_ID_ATTR_NAME))
				.cast(String.class)
				.switchIfEmpty(clientRegistrationId(authentication));
	}

	private Mono<String> clientRegistrationId(Authentication authentication) {
		return Mono.justOrEmpty(authentication)
				.filter(t -> this.defaultOAuth2AuthorizedClient && t instanceof OAuth2AuthenticationToken)
				.cast(OAuth2AuthenticationToken.class)
				.map(OAuth2AuthenticationToken::getAuthorizedClientRegistrationId);
	}

	private Mono<OAuth2AuthorizedClient> loadAuthorizedClient(String clientRegistrationId,
			ServerWebExchange exchange, Authentication principal) {
		return this.authorizedClientRepository.loadAuthorizedClient(clientRegistrationId, principal, exchange)
			.switchIfEmpty(authorizedClientNotFound(clientRegistrationId, exchange));
	}

	private Mono<OAuth2AuthorizedClient> authorizedClientNotFound(String clientRegistrationId, ServerWebExchange exchange) {
		return this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId)
			.switchIfEmpty(Mono.error(() -> new IllegalArgumentException("Client Registration with id " + clientRegistrationId + " was not found")))
			.flatMap(clientRegistration -> {
				if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(clientRegistration.getAuthorizationGrantType())) {
					return clientCredentials(clientRegistration, exchange);
				}
				return Mono.error(() -> new ClientAuthorizationRequiredException(clientRegistrationId));
			});
	}

	private Mono<? extends OAuth2AuthorizedClient> clientCredentials(
			ClientRegistration clientRegistration, ServerWebExchange exchange) {
		OAuth2ClientCredentialsGrantRequest grantRequest = new OAuth2ClientCredentialsGrantRequest(clientRegistration);
		return this.clientCredentialsTokenResponseClient.getTokenResponse(grantRequest)
			.flatMap(tokenResponse -> clientCredentialsResponse(clientRegistration, tokenResponse, exchange));
	}

	private Mono<OAuth2AuthorizedClient> clientCredentialsResponse(ClientRegistration clientRegistration, OAuth2AccessTokenResponse tokenResponse, ServerWebExchange exchange) {
		return currentAuthentication()
			.flatMap(principal -> {
				OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
						clientRegistration, (principal != null ?
						principal.getName() :
						"anonymousUser"),
						tokenResponse.getAccessToken());

				return this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, principal, null)
						.thenReturn(authorizedClient);
			});
	}

	private Mono<OAuth2AuthorizedClient> refreshIfNecessary(ExchangeFunction next, OAuth2AuthorizedClient authorizedClient, ClientRequest request) {
		if (shouldRefresh(authorizedClient)) {
			return serverWebExchange(request)
				.flatMap(exchange -> refreshAuthorizedClient(next, authorizedClient, exchange));
		}
		return Mono.just(authorizedClient);
	}

	private Mono<OAuth2AuthorizedClient> refreshAuthorizedClient(ExchangeFunction next,
			OAuth2AuthorizedClient authorizedClient, ServerWebExchange exchange) {
		ClientRegistration clientRegistration = authorizedClient
				.getClientRegistration();
		String tokenUri = clientRegistration
				.getProviderDetails().getTokenUri();
		ClientRequest request = ClientRequest.create(HttpMethod.POST, URI.create(tokenUri))
				.header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
				.headers(headers -> headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret()))
				.body(refreshTokenBody(authorizedClient.getRefreshToken().getTokenValue()))
				.build();
		return next.exchange(request)
				.flatMap(response -> response.body(oauth2AccessTokenResponse()))
				.map(accessTokenResponse -> new OAuth2AuthorizedClient(authorizedClient.getClientRegistration(), authorizedClient.getPrincipalName(), accessTokenResponse.getAccessToken(), accessTokenResponse.getRefreshToken()))
				.flatMap(result -> currentAuthentication()
						.defaultIfEmpty(new PrincipalNameAuthentication(authorizedClient.getPrincipalName()))
						.flatMap(principal -> this.authorizedClientRepository.saveAuthorizedClient(result, principal, exchange))
						.thenReturn(result));
	}

	private Mono<Authentication> currentAuthentication() {
		return ReactiveSecurityContextHolder.getContext()
				.map(SecurityContext::getAuthentication)
				.defaultIfEmpty(ANONYMOUS_USER_TOKEN);
	}

	private boolean shouldRefresh(OAuth2AuthorizedClient authorizedClient) {
		if (this.authorizedClientRepository == null) {
			return false;
		}
		OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
		if (refreshToken == null) {
			return false;
		}
		Instant now = this.clock.instant();
		Instant expiresAt = authorizedClient.getAccessToken().getExpiresAt();
		if (now.isAfter(expiresAt.minus(this.accessTokenExpiresSkew))) {
			return true;
		}
		return false;
	}

	private ClientRequest bearer(ClientRequest request, OAuth2AuthorizedClient authorizedClient) {
		return ClientRequest.from(request)
					.headers(headers -> headers.setBearerAuth(authorizedClient.getAccessToken().getTokenValue()))
					.build();
	}

	private static BodyInserters.FormInserter<String> refreshTokenBody(String refreshToken) {
		return BodyInserters
				.fromFormData("grant_type", AuthorizationGrantType.REFRESH_TOKEN.getValue())
				.with("refresh_token", refreshToken);
	}

	private static class PrincipalNameAuthentication implements Authentication {
		private final String username;

		private PrincipalNameAuthentication(String username) {
			this.username = username;
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			throw unsupported();
		}

		@Override
		public Object getCredentials() {
			throw unsupported();
		}

		@Override
		public Object getDetails() {
			throw unsupported();
		}

		@Override
		public Object getPrincipal() {
			throw unsupported();
		}

		@Override
		public boolean isAuthenticated() {
			throw unsupported();
		}

		@Override
		public void setAuthenticated(boolean isAuthenticated)
				throws IllegalArgumentException {
			throw unsupported();
		}

		@Override
		public String getName() {
			return this.username;
		}

		private UnsupportedOperationException unsupported() {
			return new UnsupportedOperationException("Not Supported");
		}
	}
}
