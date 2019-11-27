/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.oauth2.client.web.reactive.function.client;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.ClientCredentialsReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.RefreshTokenReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.UnAuthenticatedServerOAuth2AuthorizedClientRepository;
import org.springframework.util.Assert;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

/**
 * Provides an easy mechanism for using an {@link OAuth2AuthorizedClient} to make OAuth2 requests by including the
 * token as a Bearer Token.
 *
 * @author Rob Winch
 * @author Joe Grandja
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

	private ReactiveOAuth2AuthorizedClientManager authorizedClientManager;

	private boolean defaultAuthorizedClientManager;

	private boolean defaultOAuth2AuthorizedClient;

	private String defaultClientRegistrationId;

	@Deprecated
	private Duration accessTokenExpiresSkew = Duration.ofMinutes(1);

	@Deprecated
	private ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient;


	/**
	 * Constructs a {@code ServerOAuth2AuthorizedClientExchangeFilterFunction} using the provided parameters.
	 *
	 * @since 5.2
	 * @param authorizedClientManager the {@link ReactiveOAuth2AuthorizedClientManager} which manages the authorized client(s)
	 */
	public ServerOAuth2AuthorizedClientExchangeFilterFunction(ReactiveOAuth2AuthorizedClientManager authorizedClientManager) {
		Assert.notNull(authorizedClientManager, "authorizedClientManager cannot be null");
		this.authorizedClientManager = authorizedClientManager;
	}

	/**
	 * Constructs a {@code ServerOAuth2AuthorizedClientExchangeFilterFunction} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientRepository the repository of authorized clients
	 */
	public ServerOAuth2AuthorizedClientExchangeFilterFunction(ReactiveClientRegistrationRepository clientRegistrationRepository,
																ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
		this.authorizedClientManager = createDefaultAuthorizedClientManager(clientRegistrationRepository, authorizedClientRepository);
		this.defaultAuthorizedClientManager = true;
	}

	private static ReactiveOAuth2AuthorizedClientManager createDefaultAuthorizedClientManager(
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {

		ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider =
				ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
						.authorizationCode()
						.refreshToken()
						.clientCredentials()
						.password()
						.build();

		// gh-7544
		if (authorizedClientRepository instanceof UnAuthenticatedServerOAuth2AuthorizedClientRepository) {
			UnAuthenticatedReactiveOAuth2AuthorizedClientManager unauthenticatedAuthorizedClientManager =
					new UnAuthenticatedReactiveOAuth2AuthorizedClientManager(
							clientRegistrationRepository,
							(UnAuthenticatedServerOAuth2AuthorizedClientRepository) authorizedClientRepository);
			unauthenticatedAuthorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
			return unauthenticatedAuthorizedClientManager;
		}

		DefaultReactiveOAuth2AuthorizedClientManager authorizedClientManager = new DefaultReactiveOAuth2AuthorizedClientManager(
				clientRegistrationRepository, authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

		return authorizedClientManager;
	}

	/**
	 * Modifies the {@link ClientRequest#attributes()} to include the {@link OAuth2AuthorizedClient} to be used for
	 * providing the Bearer Token. Example usage:
	 *
	 * <pre>
	 * WebClient webClient = WebClient.builder()
	 *    .filter(new ServerOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager))
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
	 * Modifies the {@link ClientRequest#attributes()} to include the {@link ServerWebExchange} to be used for
	 * providing the Bearer Token. Example usage:
	 *
	 * <pre>
	 * WebClient webClient = WebClient.builder()
	 *    .filter(new ServerOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager))
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
	 * Sets the {@link ReactiveOAuth2AccessTokenResponseClient} used for getting an {@link OAuth2AuthorizedClient} for the client_credentials grant.
	 *
	 * @deprecated Use {@link #ServerOAuth2AuthorizedClientExchangeFilterFunction(ReactiveOAuth2AuthorizedClientManager)} instead.
	 * 				Create an instance of {@link ClientCredentialsReactiveOAuth2AuthorizedClientProvider} configured with a
	 * 				{@link ClientCredentialsReactiveOAuth2AuthorizedClientProvider#setAccessTokenResponseClient(ReactiveOAuth2AccessTokenResponseClient) WebClientReactiveClientCredentialsTokenResponseClient}
	 * 				(or a custom one) and than supply it to {@link DefaultReactiveOAuth2AuthorizedClientManager#setAuthorizedClientProvider(ReactiveOAuth2AuthorizedClientProvider) DefaultReactiveOAuth2AuthorizedClientManager}.
	 *
	 * @param clientCredentialsTokenResponseClient the client to use
	 */
	@Deprecated
	public void setClientCredentialsTokenResponseClient(
			ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient) {
		Assert.notNull(clientCredentialsTokenResponseClient, "clientCredentialsTokenResponseClient cannot be null");
		Assert.state(this.defaultAuthorizedClientManager, "The client cannot be set when the constructor used is \"ServerOAuth2AuthorizedClientExchangeFilterFunction(ReactiveOAuth2AuthorizedClientManager)\". " +
				"Instead, use the constructor \"ServerOAuth2AuthorizedClientExchangeFilterFunction(ClientRegistrationRepository, OAuth2AuthorizedClientRepository)\".");
		this.clientCredentialsTokenResponseClient = clientCredentialsTokenResponseClient;
		updateDefaultAuthorizedClientManager();
	}

	private void updateDefaultAuthorizedClientManager() {
		ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider =
				ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
						.authorizationCode()
						.refreshToken(configurer -> configurer.clockSkew(this.accessTokenExpiresSkew))
						.clientCredentials(this::updateClientCredentialsProvider)
						.password(configurer -> configurer.clockSkew(this.accessTokenExpiresSkew))
						.build();
		if (this.authorizedClientManager instanceof UnAuthenticatedReactiveOAuth2AuthorizedClientManager) {
			((UnAuthenticatedReactiveOAuth2AuthorizedClientManager) this.authorizedClientManager).setAuthorizedClientProvider(authorizedClientProvider);
		} else {
			((DefaultReactiveOAuth2AuthorizedClientManager) this.authorizedClientManager).setAuthorizedClientProvider(authorizedClientProvider);
		}
	}

	private void updateClientCredentialsProvider(ReactiveOAuth2AuthorizedClientProviderBuilder.ClientCredentialsGrantBuilder builder) {
		if (this.clientCredentialsTokenResponseClient != null) {
			builder.accessTokenResponseClient(this.clientCredentialsTokenResponseClient);
		}
		builder.clockSkew(this.accessTokenExpiresSkew);
	}

	/**
	 * An access token will be considered expired by comparing its expiration to now +
	 * this skewed Duration. The default is 1 minute.
	 *
	 * @deprecated The {@code accessTokenExpiresSkew} should be configured with the specific {@link ReactiveOAuth2AuthorizedClientProvider} implementation,
	 * 				e.g. {@link ClientCredentialsReactiveOAuth2AuthorizedClientProvider#setClockSkew(Duration) ClientCredentialsReactiveOAuth2AuthorizedClientProvider} or
	 * 				{@link RefreshTokenReactiveOAuth2AuthorizedClientProvider#setClockSkew(Duration) RefreshTokenReactiveOAuth2AuthorizedClientProvider}.
	 *
	 * @param accessTokenExpiresSkew the Duration to use.
	 */
	@Deprecated
	public void setAccessTokenExpiresSkew(Duration accessTokenExpiresSkew) {
		Assert.notNull(accessTokenExpiresSkew, "accessTokenExpiresSkew cannot be null");
		Assert.state(this.defaultAuthorizedClientManager, "The accessTokenExpiresSkew cannot be set when the constructor used is \"ServerOAuth2AuthorizedClientExchangeFilterFunction(ReactiveOAuth2AuthorizedClientManager)\". " +
				"Instead, use the constructor \"ServerOAuth2AuthorizedClientExchangeFilterFunction(ClientRegistrationRepository, OAuth2AuthorizedClientRepository)\".");
		this.accessTokenExpiresSkew = accessTokenExpiresSkew;
		updateDefaultAuthorizedClientManager();
	}

	@Override
	public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
		return authorizedClient(request)
				.map(authorizedClient -> bearer(request, authorizedClient))
				.flatMap(next::exchange)
				.switchIfEmpty(Mono.defer(() -> next.exchange(request)));
	}

	private Mono<OAuth2AuthorizedClient> authorizedClient(ClientRequest request) {
		OAuth2AuthorizedClient authorizedClientFromAttrs = oauth2AuthorizedClient(request);
		return Mono.justOrEmpty(authorizedClientFromAttrs)
				.switchIfEmpty(Mono.defer(() ->
						authorizeRequest(request).flatMap(this.authorizedClientManager::authorize)))
				.flatMap(authorizedClient ->
						reauthorizeRequest(request, authorizedClient).flatMap(this.authorizedClientManager::authorize));
	}

	private Mono<OAuth2AuthorizeRequest> authorizeRequest(ClientRequest request) {
		Mono<Authentication> authentication = currentAuthentication();

		Mono<String> clientRegistrationId = Mono.justOrEmpty(clientRegistrationId(request))
				.switchIfEmpty(Mono.justOrEmpty(this.defaultClientRegistrationId))
				.switchIfEmpty(clientRegistrationId(authentication));

		Mono<Optional<ServerWebExchange>> serverWebExchange = Mono.justOrEmpty(serverWebExchange(request))
				.switchIfEmpty(currentServerWebExchange())
				.map(Optional::of)
				.defaultIfEmpty(Optional.empty());

		return Mono.zip(clientRegistrationId, authentication, serverWebExchange)
				.map(t3 -> {
					OAuth2AuthorizeRequest.Builder builder = OAuth2AuthorizeRequest.withClientRegistrationId(t3.getT1()).principal(t3.getT2());
					if (t3.getT3().isPresent()) {
						builder.attribute(ServerWebExchange.class.getName(), t3.getT3().get());
					}
					return builder.build();
				});
	}

	private Mono<OAuth2AuthorizeRequest> reauthorizeRequest(ClientRequest request, OAuth2AuthorizedClient authorizedClient) {
		Mono<Authentication> authentication = currentAuthentication();

		Mono<Optional<ServerWebExchange>> serverWebExchange = Mono.justOrEmpty(serverWebExchange(request))
				.switchIfEmpty(currentServerWebExchange())
				.map(Optional::of)
				.defaultIfEmpty(Optional.empty());

		return Mono.zip(authentication, serverWebExchange)
				.map(t2 -> {
					OAuth2AuthorizeRequest.Builder builder = OAuth2AuthorizeRequest.withAuthorizedClient(authorizedClient).principal(t2.getT1());
					if (t2.getT2().isPresent()) {
						builder.attribute(ServerWebExchange.class.getName(), t2.getT2().get());
					}
					return builder.build();
				});
	}

	private Mono<Authentication> currentAuthentication() {
		return ReactiveSecurityContextHolder.getContext()
				.map(SecurityContext::getAuthentication)
				.defaultIfEmpty(ANONYMOUS_USER_TOKEN);
	}

	private Mono<String> clientRegistrationId(Mono<Authentication> authentication) {
		return authentication
				.filter(t -> this.defaultOAuth2AuthorizedClient && t instanceof OAuth2AuthenticationToken)
				.cast(OAuth2AuthenticationToken.class)
				.map(OAuth2AuthenticationToken::getAuthorizedClientRegistrationId);
	}

	private Mono<ServerWebExchange> currentServerWebExchange() {
		return Mono.subscriberContext()
				.filter(c -> c.hasKey(ServerWebExchange.class))
				.map(c -> c.get(ServerWebExchange.class));
	}

	private ClientRequest bearer(ClientRequest request, OAuth2AuthorizedClient authorizedClient) {
		return ClientRequest.from(request)
					.headers(headers -> headers.setBearerAuth(authorizedClient.getAccessToken().getTokenValue()))
					.build();
	}

	private static class UnAuthenticatedReactiveOAuth2AuthorizedClientManager implements ReactiveOAuth2AuthorizedClientManager {
		private final ReactiveClientRegistrationRepository clientRegistrationRepository;
		private final UnAuthenticatedServerOAuth2AuthorizedClientRepository authorizedClientRepository;
		private ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider;

		private UnAuthenticatedReactiveOAuth2AuthorizedClientManager(
				ReactiveClientRegistrationRepository clientRegistrationRepository,
				UnAuthenticatedServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
			this.clientRegistrationRepository = clientRegistrationRepository;
			this.authorizedClientRepository = authorizedClientRepository;
		}

		@Override
		public Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizeRequest authorizeRequest) {
			Assert.notNull(authorizeRequest, "authorizeRequest cannot be null");

			String clientRegistrationId = authorizeRequest.getClientRegistrationId();
			Authentication principal = authorizeRequest.getPrincipal();

			return Mono.justOrEmpty(authorizeRequest.getAuthorizedClient())
					.switchIfEmpty(Mono.defer(() -> this.authorizedClientRepository.loadAuthorizedClient(clientRegistrationId, principal, null)))
					.flatMap(authorizedClient -> {
						// Re-authorize
						return Mono.just(OAuth2AuthorizationContext.withAuthorizedClient(authorizedClient).principal(principal).build())
								.flatMap(this.authorizedClientProvider::authorize)
								.flatMap(reauthorizedClient -> this.authorizedClientRepository.saveAuthorizedClient(reauthorizedClient, principal, null).thenReturn(reauthorizedClient))
								// Default to the existing authorizedClient if the client was not re-authorized
								.defaultIfEmpty(authorizeRequest.getAuthorizedClient() != null ?
										authorizeRequest.getAuthorizedClient() : authorizedClient);
					})
					.switchIfEmpty(Mono.deferWithContext(context ->
						// Authorize
						this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId)
								.switchIfEmpty(Mono.error(() -> new IllegalArgumentException(
										"Could not find ClientRegistration with id '" + clientRegistrationId + "'")))
								.flatMap(clientRegistration -> Mono.just(OAuth2AuthorizationContext.withClientRegistration(clientRegistration).principal(principal).build()))
								.flatMap(this.authorizedClientProvider::authorize)
								.flatMap(authorizedClient -> this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, principal, null).thenReturn(authorizedClient))
								.subscriberContext(context)
					));
		}

		private void setAuthorizedClientProvider(ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider) {
			Assert.notNull(authorizedClientProvider, "authorizedClientProvider cannot be null");
			this.authorizedClientProvider = authorizedClientProvider;
		}
	}
}
