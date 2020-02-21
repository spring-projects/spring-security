/*
 * Copyright 2002-2020 the original author or authors.
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

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.ClientCredentialsReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizationSuccessHandler;
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
import org.springframework.security.oauth2.client.web.RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.web.SaveAuthorizedClientReactiveOAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.UnAuthenticatedServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Provides an easy mechanism for using an {@link OAuth2AuthorizedClient} to make OAuth2 requests by including the
 * token as a Bearer Token.
 *
 * <h3>Authentication and Authorization Failures</h3>
 *
 * <p>Since 5.3, this filter function has the ability to forward authentication (HTTP 401 Unauthorized)
 * and authorization (HTTP 403 Forbidden) failures from an OAuth 2.0 Resource Server to a
 * {@link ReactiveOAuth2AuthorizationFailureHandler}.
 * A {@link RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler} can be used
 * to remove the cached {@link OAuth2AuthorizedClient}, so that future requests will result
 * in a new token being retrieved from an Authorization Server, and sent to the Resource Server.</p>
 *
 * <p>If the {@link #ServerOAuth2AuthorizedClientExchangeFilterFunction(ReactiveClientRegistrationRepository, ServerOAuth2AuthorizedClientRepository)}
 * constructor is used, a {@link RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler}
 * will be configured automatically.</p>
 *
 * <p>If the {@link #ServerOAuth2AuthorizedClientExchangeFilterFunction(ReactiveOAuth2AuthorizedClientManager)}
 * constructor is used, a {@link RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler}
 * will <em>NOT</em> be configured automatically.
 * It is recommended that you configure one via {@link #setAuthorizationFailureHandler(ReactiveOAuth2AuthorizationFailureHandler)}.</p>
 *
 * @author Rob Winch
 * @author Joe Grandja
 * @author Phil Clay
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

	private final Mono<Authentication> currentAuthenticationMono = ReactiveSecurityContextHolder.getContext()
			.map(SecurityContext::getAuthentication)
			.defaultIfEmpty(ANONYMOUS_USER_TOKEN);

	private final Mono<String> clientRegistrationIdMono = currentAuthenticationMono
			.filter(t -> this.defaultOAuth2AuthorizedClient && t instanceof OAuth2AuthenticationToken)
			.cast(OAuth2AuthenticationToken.class)
			.map(OAuth2AuthenticationToken::getAuthorizedClientRegistrationId);

	private final Mono<ServerWebExchange> currentServerWebExchangeMono = Mono.subscriberContext()
			.filter(c -> c.hasKey(ServerWebExchange.class))
			.map(c -> c.get(ServerWebExchange.class));

	private final ReactiveOAuth2AuthorizedClientManager authorizedClientManager;

	private boolean defaultAuthorizedClientManager;

	private boolean defaultOAuth2AuthorizedClient;

	private String defaultClientRegistrationId;

	@Deprecated
	private Duration accessTokenExpiresSkew = Duration.ofMinutes(1);

	@Deprecated
	private ReactiveOAuth2AccessTokenResponseClient<OAuth2ClientCredentialsGrantRequest> clientCredentialsTokenResponseClient;

	private ClientResponseHandler clientResponseHandler;

	@FunctionalInterface
	private interface ClientResponseHandler {
		Mono<ClientResponse> handleResponse(ClientRequest request, Mono<ClientResponse> response);
	}

	/**
	 * Constructs a {@code ServerOAuth2AuthorizedClientExchangeFilterFunction} using the provided parameters.
	 *
	 * <p>When this constructor is used, authentication (HTTP 401) and authorization (HTTP 403)
	 * failures returned from a OAuth 2.0 Resource Server will <em>NOT</em> be forwarded to a
	 * {@link ReactiveOAuth2AuthorizationFailureHandler}.
	 * Therefore, future requests to the Resource Server will most likely use the same (most likely invalid) token,
	 * resulting in the same errors returned from the Resource Server.
	 * It is recommended to configure a {@link RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler}
	 * via {@link #setAuthorizationFailureHandler(ReactiveOAuth2AuthorizationFailureHandler)}
	 * so that authentication and authorization failures returned from a Resource Server
	 * will result in removing the authorized client, so that a new token is retrieved for future requests.</p>
	 *
	 * @since 5.2
	 * @param authorizedClientManager the {@link ReactiveOAuth2AuthorizedClientManager} which manages the authorized client(s)
	 */
	public ServerOAuth2AuthorizedClientExchangeFilterFunction(ReactiveOAuth2AuthorizedClientManager authorizedClientManager) {
		Assert.notNull(authorizedClientManager, "authorizedClientManager cannot be null");
		this.authorizedClientManager = authorizedClientManager;
		this.clientResponseHandler =  (request, responseMono) -> responseMono;
	}

	/**
	 * Constructs a {@code ServerOAuth2AuthorizedClientExchangeFilterFunction} using the provided parameters.
	 *
	 * <p>Since 5.3, when this constructor is used, authentication (HTTP 401)
	 * and authorization (HTTP 403) failures returned from an OAuth 2.0 Resource Server
	 * will be forwarded to a {@link RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler},
	 * which will potentially remove the {@link OAuth2AuthorizedClient} from the given
	 * {@link ServerOAuth2AuthorizedClientRepository}, depending on the OAuth 2.0 error code returned.
	 * Authentication failures returned from an OAuth 2.0 Resource Server typically indicate
	 * that the token is invalid, and should not be used in future requests.
	 * Removing the authorized client from the repository will ensure that the existing
	 * token will not be sent for future requests to the Resource Server,
	 * and a new token is retrieved from Authorization Server and used for
	 * future requests to the Resource Server.</p>
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientRepository the repository of authorized clients
	 */
	public ServerOAuth2AuthorizedClientExchangeFilterFunction(ReactiveClientRegistrationRepository clientRegistrationRepository,
																ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {

		ReactiveOAuth2AuthorizationFailureHandler authorizationFailureHandler =
				new RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler(authorizedClientRepository);

		this.authorizedClientManager = createDefaultAuthorizedClientManager(
				clientRegistrationRepository,
				authorizedClientRepository,
				authorizationFailureHandler);
		this.clientResponseHandler = new AuthorizationFailureForwarder(authorizationFailureHandler);
		this.defaultAuthorizedClientManager = true;
	}

	private static ReactiveOAuth2AuthorizedClientManager createDefaultAuthorizedClientManager(
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			ServerOAuth2AuthorizedClientRepository authorizedClientRepository,
			ReactiveOAuth2AuthorizationFailureHandler authorizationFailureHandler) {

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
							(UnAuthenticatedServerOAuth2AuthorizedClientRepository) authorizedClientRepository,
							authorizationFailureHandler);
			unauthenticatedAuthorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
			return unauthenticatedAuthorizedClientManager;
		}

		DefaultReactiveOAuth2AuthorizedClientManager authorizedClientManager = new DefaultReactiveOAuth2AuthorizedClientManager(
				clientRegistrationRepository, authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
		authorizedClientManager.setAuthorizationFailureHandler(authorizationFailureHandler);

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
				.flatMap(requestWithBearer -> exchangeAndHandleResponse(requestWithBearer, next))
				.switchIfEmpty(Mono.defer(() -> exchangeAndHandleResponse(request, next)));
	}

	private Mono<ClientResponse> exchangeAndHandleResponse(ClientRequest request, ExchangeFunction next) {
		return next.exchange(request)
				.transform(responseMono -> this.clientResponseHandler.handleResponse(request, responseMono));
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
		Mono<String> clientRegistrationId = effectiveClientRegistrationId(request);

		Mono<Optional<ServerWebExchange>> serverWebExchange = effectiveServerWebExchange(request);

		return Mono.zip(clientRegistrationId, this.currentAuthenticationMono, serverWebExchange)
				.map(t3 -> {
					OAuth2AuthorizeRequest.Builder builder = OAuth2AuthorizeRequest.withClientRegistrationId(t3.getT1()).principal(t3.getT2());
					t3.getT3().ifPresent(exchange -> builder.attribute(ServerWebExchange.class.getName(), exchange));
					return builder.build();
				});
	}

	/**
	 * Returns a {@link Mono} the emits the {@code clientRegistrationId}
	 * that is active for the given request.
	 *
	 * @param request the request for which to retrieve the {@code clientRegistrationId}
	 * @return a mono that emits the {@code clientRegistrationId}
	 * 	       that is active for the given request.
	 */
	private Mono<String> effectiveClientRegistrationId(ClientRequest request) {
		return Mono.justOrEmpty(clientRegistrationId(request))
				.switchIfEmpty(Mono.justOrEmpty(this.defaultClientRegistrationId))
				.switchIfEmpty(clientRegistrationIdMono);
	}

	/**
	 * Returns a {@link Mono} that emits an {@link Optional} for the {@link ServerWebExchange}
	 * that is active for the given request.
	 *
	 * <p>The returned {@link Mono} will never complete empty.
	 * Instead, it will emit an empty {@link Optional} if no exchange is active.</p>
	 *
	 * @param request the request for which to retrieve the exchange
	 * @return a {@link Mono} that emits an {@link Optional} for the {@link ServerWebExchange}
	 * 	       that is active for the given request.
	 */
	private Mono<Optional<ServerWebExchange>> effectiveServerWebExchange(ClientRequest request) {
		return Mono.justOrEmpty(serverWebExchange(request))
				.switchIfEmpty(currentServerWebExchangeMono)
				.map(Optional::of)
				.defaultIfEmpty(Optional.empty());
	}

	private Mono<OAuth2AuthorizeRequest> reauthorizeRequest(ClientRequest request, OAuth2AuthorizedClient authorizedClient) {
		Mono<Optional<ServerWebExchange>> serverWebExchange = effectiveServerWebExchange(request);

		return Mono.zip(this.currentAuthenticationMono, serverWebExchange)
				.map(t2 -> {
					OAuth2AuthorizeRequest.Builder builder = OAuth2AuthorizeRequest.withAuthorizedClient(authorizedClient).principal(t2.getT1());
					t2.getT2().ifPresent(exchange -> builder.attribute(ServerWebExchange.class.getName(), exchange));
					return builder.build();
				});
	}

	private ClientRequest bearer(ClientRequest request, OAuth2AuthorizedClient authorizedClient) {
		return ClientRequest.from(request)
					.headers(headers -> headers.setBearerAuth(authorizedClient.getAccessToken().getTokenValue()))
					.build();
	}

	/**
	 * Sets the handler that handles authentication and authorization failures when communicating
	 * to the OAuth 2.0 Resource Server.
	 *
	 * <p>For example, a {@link RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler}
	 * is typically used to remove the cached {@link OAuth2AuthorizedClient},
	 * so that the same token is no longer used in future requests to the Resource Server.</p>
	 *
	 * <p>The failure handler used by default depends on which constructor was used
	 * to construct this {@link ServerOAuth2AuthorizedClientExchangeFilterFunction}.
	 * See the constructors for more details.</p>
	 *
	 * @param authorizationFailureHandler the handler that handles authentication and authorization failures.
	 * @since 5.3
	 */
	public void setAuthorizationFailureHandler(ReactiveOAuth2AuthorizationFailureHandler authorizationFailureHandler) {
		Assert.notNull(authorizationFailureHandler, "authorizationFailureHandler cannot be null");
		this.clientResponseHandler = new AuthorizationFailureForwarder(authorizationFailureHandler);
	}

	private static class UnAuthenticatedReactiveOAuth2AuthorizedClientManager implements ReactiveOAuth2AuthorizedClientManager {
		private final ReactiveClientRegistrationRepository clientRegistrationRepository;
		private final UnAuthenticatedServerOAuth2AuthorizedClientRepository authorizedClientRepository;
		private final ReactiveOAuth2AuthorizationSuccessHandler authorizationSuccessHandler;
		private final ReactiveOAuth2AuthorizationFailureHandler authorizationFailureHandler;
		private ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider;

		private UnAuthenticatedReactiveOAuth2AuthorizedClientManager(
				ReactiveClientRegistrationRepository clientRegistrationRepository,
				UnAuthenticatedServerOAuth2AuthorizedClientRepository authorizedClientRepository,
				ReactiveOAuth2AuthorizationFailureHandler authorizationFailureHandler) {
			this.clientRegistrationRepository = clientRegistrationRepository;
			this.authorizedClientRepository = authorizedClientRepository;
			this.authorizationSuccessHandler = new SaveAuthorizedClientReactiveOAuth2AuthorizationSuccessHandler(authorizedClientRepository);
			this.authorizationFailureHandler = authorizationFailureHandler;
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
								.flatMap(authorizationContext -> authorize(authorizationContext, principal))
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
								.flatMap(authorizationContext -> authorize(authorizationContext, principal))
								.subscriberContext(context)
					));
		}

		/**
		 * Performs authorization and then delegates to either the {@link #authorizationSuccessHandler}
		 * or {@link #authorizationFailureHandler}, depending on the authorization result.
		 *
		 * @param authorizationContext the context to authorize
		 * @param principal the principle to authorize
		 * @return a {@link Mono} that emits the authorized client after the authorization attempt succeeds
		 *         and the {@link #authorizationSuccessHandler} has completed,
		 *         or completes with an exception after the authorization attempt fails
		 *         and the {@link #authorizationFailureHandler} has completed
		 */
		private Mono<OAuth2AuthorizedClient> authorize(
				OAuth2AuthorizationContext authorizationContext,
				Authentication principal) {

			return this.authorizedClientProvider.authorize(authorizationContext)
					// Delegates to the authorizationSuccessHandler of the successful authorization
					.flatMap(authorizedClient -> this.authorizationSuccessHandler.onAuthorizationSuccess(
									authorizedClient,
									principal,
									Collections.emptyMap())
							.thenReturn(authorizedClient))
					// Delegates to  the authorizationFailureHandler of the failed authorization
					.onErrorResume(OAuth2AuthorizationException.class, authorizationException -> this.authorizationFailureHandler.onAuthorizationFailure(
									authorizationException,
									principal,
									Collections.emptyMap())
							.then(Mono.error(authorizationException)));
		}

		private void setAuthorizedClientProvider(ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider) {
			Assert.notNull(authorizedClientProvider, "authorizedClientProvider cannot be null");
			this.authorizedClientProvider = authorizedClientProvider;
		}
	}

	/**
	 * Forwards authentication and authorization failures to a
	 * {@link ReactiveOAuth2AuthorizationFailureHandler}.
	 *
	 * @since 5.3
	 */
	private class AuthorizationFailureForwarder implements ClientResponseHandler {

		/**
		 * A map of HTTP Status Code to OAuth 2.0 Error codes for
		 * HTTP status codes that should be interpreted as
		 * authentication or authorization failures.
		 */
		private final Map<Integer, String> httpStatusToOAuth2ErrorCodeMap;

		/**
		 * The {@link ReactiveOAuth2AuthorizationFailureHandler} to notify
		 * when an authentication/authorization failure occurs.
		 */
		private final ReactiveOAuth2AuthorizationFailureHandler authorizationFailureHandler;

		private AuthorizationFailureForwarder(ReactiveOAuth2AuthorizationFailureHandler authorizationFailureHandler) {
			Assert.notNull(authorizationFailureHandler, "authorizationFailureHandler cannot be null");
			this.authorizationFailureHandler = authorizationFailureHandler;

			Map<Integer, String> httpStatusToOAuth2Error = new HashMap<>();
			httpStatusToOAuth2Error.put(HttpStatus.UNAUTHORIZED.value(), OAuth2ErrorCodes.INVALID_TOKEN);
			httpStatusToOAuth2Error.put(HttpStatus.FORBIDDEN.value(), OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
			this.httpStatusToOAuth2ErrorCodeMap = Collections.unmodifiableMap(httpStatusToOAuth2Error);
		}

		@Override
		public Mono<ClientResponse> handleResponse(ClientRequest request, Mono<ClientResponse> responseMono) {
			return responseMono
				.flatMap(response -> handleResponse(request, response)
						.thenReturn(response))
				.onErrorResume(WebClientResponseException.class, e -> handleWebClientResponseException(request, e)
						.then(Mono.error(e)))
				.onErrorResume(OAuth2AuthorizationException.class, e -> handleAuthorizationException(request, e)
						.then(Mono.error(e)));
		}

		private Mono<Void> handleResponse(ClientRequest request, ClientResponse response) {
			return Mono.justOrEmpty(resolveErrorIfPossible(response))
					.flatMap(oauth2Error -> {
						Mono<Optional<ServerWebExchange>> serverWebExchange = effectiveServerWebExchange(request);

						Mono<String> clientRegistrationId = effectiveClientRegistrationId(request);

						return Mono.zip(currentAuthenticationMono, serverWebExchange, clientRegistrationId)
								.flatMap(tuple3 -> handleAuthorizationFailure(
										tuple3.getT1(),              // Authentication principal
										tuple3.getT2().orElse(null), // ServerWebExchange exchange
										new ClientAuthorizationException(
												oauth2Error,
												tuple3.getT3())));      // String clientRegistrationId
					});
		}

		private OAuth2Error resolveErrorIfPossible(ClientResponse response) {
			// Try to resolve from 'WWW-Authenticate' header
			if (!response.headers().header(HttpHeaders.WWW_AUTHENTICATE).isEmpty()) {
				String wwwAuthenticateHeader = response.headers().header(HttpHeaders.WWW_AUTHENTICATE).get(0);
				Map<String, String> authParameters = parseAuthParameters(wwwAuthenticateHeader);
				if (authParameters.containsKey(OAuth2ParameterNames.ERROR)) {
					return new OAuth2Error(
							authParameters.get(OAuth2ParameterNames.ERROR),
							authParameters.get(OAuth2ParameterNames.ERROR_DESCRIPTION),
							authParameters.get(OAuth2ParameterNames.ERROR_URI));
				}
			}
			return resolveErrorIfPossible(response.rawStatusCode());
		}

		private OAuth2Error resolveErrorIfPossible(int statusCode) {
			if (this.httpStatusToOAuth2ErrorCodeMap.containsKey(statusCode)) {
				return new OAuth2Error(
						this.httpStatusToOAuth2ErrorCodeMap.get(statusCode),
						null,
						"https://tools.ietf.org/html/rfc6750#section-3.1");
			}
			return null;
		}

		private Map<String, String> parseAuthParameters(String wwwAuthenticateHeader) {
			return Stream.of(wwwAuthenticateHeader)
					.filter(header -> !StringUtils.isEmpty(header))
					.filter(header -> header.toLowerCase().startsWith("bearer"))
					.map(header -> header.substring("bearer".length()))
					.map(header -> header.split(","))
					.flatMap(Stream::of)
					.map(parameter -> parameter.split("="))
					.filter(parameter -> parameter.length > 1)
					.collect(Collectors.toMap(
							parameters -> parameters[0].trim(),
							parameters -> parameters[1].trim().replace("\"", "")));
		}

		/**
		 * Handles the given http status code returned from a resource server
		 * by notifying the authorization failure handler if the http status
		 * code is in the {@link #httpStatusToOAuth2ErrorCodeMap}.
		 *
		 * @param request the request being processed
		 * @param exception The root cause exception for the failure
		 * @return a {@link Mono} that completes empty after the authorization failure handler completes.
		 */
		private Mono<Void> handleWebClientResponseException(ClientRequest request, WebClientResponseException exception) {
			return Mono.justOrEmpty(resolveErrorIfPossible(exception.getRawStatusCode()))
					.flatMap(oauth2Error -> {
						Mono<Optional<ServerWebExchange>> serverWebExchange = effectiveServerWebExchange(request);

						Mono<String> clientRegistrationId = effectiveClientRegistrationId(request);

						return Mono.zip(currentAuthenticationMono, serverWebExchange, clientRegistrationId)
								.flatMap(tuple3 -> handleAuthorizationFailure(
										tuple3.getT1(),              // Authentication principal
										tuple3.getT2().orElse(null), // ServerWebExchange exchange
										new ClientAuthorizationException(
												oauth2Error,
												tuple3.getT3(),      // String clientRegistrationId
												exception)));
					});
		}

		/**
		 * Handles the given OAuth2AuthorizationException that occurred downstream
		 * by notifying the authorization failure handler.
		 *
		 * @param request the request being processed
		 * @param exception the authorization exception to include in the failure event.
		 * @return a {@link Mono} that completes empty after the authorization failure handler completes.
		 */
		private Mono<Void> handleAuthorizationException(ClientRequest request, OAuth2AuthorizationException exception) {
			Mono<Optional<ServerWebExchange>> serverWebExchange = effectiveServerWebExchange(request);

			return Mono.zip(currentAuthenticationMono, serverWebExchange)
					.flatMap(tuple2 -> handleAuthorizationFailure(
							tuple2.getT1(),              // Authentication principal
							tuple2.getT2().orElse(null), // ServerWebExchange exchange
							exception));
		}

		/**
		 * Delegates to the authorization failure handler of the failed authorization.
		 *
		 * @param principal the principal associated with the failed authorization attempt
		 * @param exchange the currently active exchange
		 * @param exception the authorization exception to include in the failure event.
		 * @return a {@link Mono} that completes empty after the authorization failure handler completes.
		 */
		private Mono<Void> handleAuthorizationFailure(
				Authentication principal,
				ServerWebExchange exchange,
				OAuth2AuthorizationException exception) {

			return this.authorizationFailureHandler.onAuthorizationFailure(
					exception,
					principal,
					createAttributes(exchange));
		}

		private Map<String, Object> createAttributes(ServerWebExchange exchange) {
			if (exchange == null) {
				return Collections.emptyMap();
			}
			return Collections.singletonMap(ServerWebExchange.class.getName(), exchange);
		}
	}
}
