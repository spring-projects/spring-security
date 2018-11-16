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

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
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
import java.util.Map;
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

	private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

	private final OAuth2AuthorizedClientResolver authorizedClientResolver;

	public ServerOAuth2AuthorizedClientExchangeFilterFunction(ReactiveClientRegistrationRepository clientRegistrationRepository, ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
		this(authorizedClientRepository, new OAuth2AuthorizedClientResolver(clientRegistrationRepository, authorizedClientRepository));
	}

	ServerOAuth2AuthorizedClientExchangeFilterFunction(ServerOAuth2AuthorizedClientRepository authorizedClientRepository, OAuth2AuthorizedClientResolver authorizedClientResolver) {
		this.authorizedClientRepository = authorizedClientRepository;
		this.authorizedClientResolver = authorizedClientResolver;
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

	private static OAuth2AuthorizedClient oauth2AuthorizedClient(ClientRequest request) {
		return (OAuth2AuthorizedClient) request.attributes().get(OAUTH2_AUTHORIZED_CLIENT_ATTR_NAME);
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

	private static ServerWebExchange serverWebExchange(ClientRequest request) {
		return (ServerWebExchange) request.attributes().get(SERVER_WEB_EXCHANGE_ATTR_NAME);
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

	private static String clientRegistrationId(ClientRequest request) {
		OAuth2AuthorizedClient authorizedClient = oauth2AuthorizedClient(request);
		if (authorizedClient != null) {
			return authorizedClient.getClientRegistration().getRegistrationId();
		}
		return (String) request.attributes().get(CLIENT_REGISTRATION_ID_ATTR_NAME);
	}

	/**
	 * If true, a default {@link OAuth2AuthorizedClient} can be discovered from the current Authentication. It is
	 * recommended to be cautious with this feature since all HTTP requests will receive the access token if it can be
	 * resolved from the current Authentication.
	 * @param defaultOAuth2AuthorizedClient true if a default {@link OAuth2AuthorizedClient} should be used, else false.
	 *                                      Default is false.
	 */
	public void setDefaultOAuth2AuthorizedClient(boolean defaultOAuth2AuthorizedClient) {
		this.authorizedClientResolver.setDefaultOAuth2AuthorizedClient(defaultOAuth2AuthorizedClient);
	}

	/**
	 * If set, will be used as the default {@link ClientRegistration#getRegistrationId()}. It is
	 * recommended to be cautious with this feature since all HTTP requests will receive the access token.
	 * @param clientRegistrationId the id to use
	 */
	public void setDefaultClientRegistrationId(String clientRegistrationId) {
		this.authorizedClientResolver.setDefaultClientRegistrationId(clientRegistrationId);
	}

	/**
	 * Sets the {@link ReactiveOAuth2AccessTokenResponseClient} to be used for getting an {@link OAuth2AuthorizedClient} for
	 * client_credentials grant.
	 * @param clientCredentialsTokenResponseClient the client to use
	 */
	public void setClientCredentialsTokenResponseClient(
			ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient) {
		this.authorizedClientResolver.setClientCredentialsTokenResponseClient(clientCredentialsTokenResponseClient);
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
		return authorizedClient(request, next)
				.map(authorizedClient -> bearer(request, authorizedClient))
				.flatMap(next::exchange)
				.switchIfEmpty(next.exchange(request));
	}

	private Mono<OAuth2AuthorizedClient> authorizedClient(ClientRequest request, ExchangeFunction next) {
		OAuth2AuthorizedClient authorizedClientFromAttrs = oauth2AuthorizedClient(request);
		return Mono.justOrEmpty(authorizedClientFromAttrs)
				.switchIfEmpty(Mono.defer(() -> loadAuthorizedClient(request)))
				.flatMap(authorizedClient -> refreshIfNecessary(request, next, authorizedClient));
	}

	private Mono<OAuth2AuthorizedClient> loadAuthorizedClient(ClientRequest request) {
		return createRequest(request)
			.flatMap(r -> this.authorizedClientResolver.loadAuthorizedClient(r));
	}

	private Mono<OAuth2AuthorizedClientResolver.Request> createRequest(ClientRequest request) {
		String clientRegistrationId = clientRegistrationId(request);
		Authentication authentication = null;
		ServerWebExchange exchange = serverWebExchange(request);
		return this.authorizedClientResolver.createDefaultedRequest(clientRegistrationId, authentication, exchange);
	}

	private Mono<OAuth2AuthorizedClient> refreshIfNecessary(ClientRequest request, ExchangeFunction next, OAuth2AuthorizedClient authorizedClient) {
		ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
		if (isClientCredentialsGrantType(clientRegistration) && hasTokenExpired(authorizedClient)) {
			return createRequest(request)
					.flatMap(r -> authorizeWithClientCredentials(clientRegistration, r));
		} else if (shouldRefresh(authorizedClient)) {
			return createRequest(request)
				.flatMap(r -> refreshAuthorizedClient(next, authorizedClient, r));
		}
		return Mono.just(authorizedClient);
	}

	private boolean isClientCredentialsGrantType(ClientRegistration clientRegistration) {
		return AuthorizationGrantType.CLIENT_CREDENTIALS.equals(clientRegistration.getAuthorizationGrantType());
	}

	private Mono<OAuth2AuthorizedClient> authorizeWithClientCredentials(ClientRegistration clientRegistration, OAuth2AuthorizedClientResolver.Request request) {
		Authentication authentication = request.getAuthentication();
		ServerWebExchange exchange = request.getExchange();

		return this.authorizedClientResolver.clientCredentials(clientRegistration, authentication, exchange).
				flatMap(result -> this.authorizedClientRepository.saveAuthorizedClient(result, authentication, exchange)
						.thenReturn(result));
	}

	private Mono<OAuth2AuthorizedClient> refreshAuthorizedClient(ExchangeFunction next,
			OAuth2AuthorizedClient authorizedClient, OAuth2AuthorizedClientResolver.Request r) {
		ServerWebExchange exchange = r.getExchange();
		Authentication authentication = r.getAuthentication();
		ClientRegistration clientRegistration = authorizedClient
				.getClientRegistration();
		String tokenUri = clientRegistration
				.getProviderDetails().getTokenUri();
		ClientRequest refreshRequest = ClientRequest.create(HttpMethod.POST, URI.create(tokenUri))
				.header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
				.headers(headers -> headers.setBasicAuth(clientRegistration.getClientId(), clientRegistration.getClientSecret()))
				.body(refreshTokenBody(authorizedClient.getRefreshToken().getTokenValue()))
				.build();
		return next.exchange(refreshRequest)
				.flatMap(refreshResponse -> refreshResponse.body(oauth2AccessTokenResponse()))
				.map(accessTokenResponse -> new OAuth2AuthorizedClient(authorizedClient.getClientRegistration(), authorizedClient.getPrincipalName(), accessTokenResponse.getAccessToken(), accessTokenResponse.getRefreshToken()))
				.flatMap(result -> this.authorizedClientRepository.saveAuthorizedClient(result, authentication, exchange)
						.thenReturn(result));
	}

	private boolean shouldRefresh(OAuth2AuthorizedClient authorizedClient) {
		if (this.authorizedClientRepository == null) {
			return false;
		}
		OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
		if (refreshToken == null) {
			return false;
		}
		return hasTokenExpired(authorizedClient);
	}

	private boolean hasTokenExpired(OAuth2AuthorizedClient authorizedClient) {
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
}
