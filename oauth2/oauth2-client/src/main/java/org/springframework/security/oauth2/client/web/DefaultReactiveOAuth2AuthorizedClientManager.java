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
package org.springframework.security.oauth2.client.web;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.SaveAuthorizedClientReactiveOAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * The default implementation of a {@link ReactiveOAuth2AuthorizedClientManager}
 * for use within the context of a {@link ServerWebExchange}.
 *
 * <p>(When operating <em>outside</em> of the context of a {@link ServerWebExchange},
 * use {@link org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager} instead.)</p>
 *
 * <p>This is a reactive equivalent of {@link DefaultOAuth2AuthorizedClientManager}.</p>
 *
 * <h2>Authorized Client Persistence</h2>
 *
 * <p>This client manager utilizes a {@link ServerOAuth2AuthorizedClientRepository}
 * to persist {@link OAuth2AuthorizedClient}s.</p>
 *
 * <p>By default, when an authorization attempt succeeds, the {@link OAuth2AuthorizedClient}
 * will be saved in the authorized client repository.
 * This functionality can be changed by configuring a custom {@link ReactiveOAuth2AuthorizationSuccessHandler}
 * via {@link #setAuthorizationFailureHandler(ReactiveOAuth2AuthorizationFailureHandler)}.</p>
 *
 * <p>By default, when an authorization attempt fails due to an
 * {@value org.springframework.security.oauth2.core.OAuth2ErrorCodes#INVALID_GRANT} error,
 * the previously saved {@link OAuth2AuthorizedClient}
 * will be removed from the authorized client repository.
 * (The {@value org.springframework.security.oauth2.core.OAuth2ErrorCodes#INVALID_GRANT}
 * error generally occurs when a refresh token that is no longer valid
 * is used to retrieve a new access token.)
 * This functionality can be changed by configuring a custom {@link ReactiveOAuth2AuthorizationFailureHandler}
 * via {@link #setAuthorizationFailureHandler(ReactiveOAuth2AuthorizationFailureHandler)}.</p>
 *
 * @author Joe Grandja
 * @author Phil Clay
 * @since 5.2
 * @see ReactiveOAuth2AuthorizedClientManager
 * @see ReactiveOAuth2AuthorizedClientProvider
 */
public final class DefaultReactiveOAuth2AuthorizedClientManager implements ReactiveOAuth2AuthorizedClientManager {

	private static final Mono<ServerWebExchange> currentServerWebExchangeMono = Mono.subscriberContext()
			.filter(c -> c.hasKey(ServerWebExchange.class))
			.map(c -> c.get(ServerWebExchange.class));

	private final ReactiveClientRegistrationRepository clientRegistrationRepository;
	private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
	private ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = context -> Mono.empty();
	private Function<OAuth2AuthorizeRequest, Mono<Map<String, Object>>> contextAttributesMapper = new DefaultContextAttributesMapper();
	private ReactiveOAuth2AuthorizationSuccessHandler authorizationSuccessHandler;
	private ReactiveOAuth2AuthorizationFailureHandler authorizationFailureHandler;

	/**
	 * Constructs a {@code DefaultReactiveOAuth2AuthorizedClientManager} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientRepository the repository of authorized clients
	 */
	public DefaultReactiveOAuth2AuthorizedClientManager(ReactiveClientRegistrationRepository clientRegistrationRepository,
														ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientRepository = authorizedClientRepository;
		this.authorizationSuccessHandler = new SaveAuthorizedClientReactiveOAuth2AuthorizationSuccessHandler(authorizedClientRepository);
		this.authorizationFailureHandler = new RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler(authorizedClientRepository);
	}

	@Override
	public Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizeRequest authorizeRequest) {
		Assert.notNull(authorizeRequest, "authorizeRequest cannot be null");

		String clientRegistrationId = authorizeRequest.getClientRegistrationId();
		Authentication principal = authorizeRequest.getPrincipal();

		return Mono.justOrEmpty(authorizeRequest.<ServerWebExchange>getAttribute(ServerWebExchange.class.getName()))
				.switchIfEmpty(currentServerWebExchangeMono)
				.switchIfEmpty(Mono.error(() -> new IllegalArgumentException("serverWebExchange cannot be null")))
				.flatMap(serverWebExchange -> Mono.justOrEmpty(authorizeRequest.getAuthorizedClient())
						.switchIfEmpty(Mono.defer(() -> loadAuthorizedClient(clientRegistrationId, principal, serverWebExchange)))
						.flatMap(authorizedClient -> {
							// Re-authorize
							return authorizationContext(authorizeRequest, authorizedClient)
									.flatMap(authorizationContext -> authorize(authorizationContext, principal, serverWebExchange))
									// Default to the existing authorizedClient if the client was not re-authorized
									.defaultIfEmpty(authorizeRequest.getAuthorizedClient() != null ?
											authorizeRequest.getAuthorizedClient() : authorizedClient);
						})
						.switchIfEmpty(Mono.deferWithContext(context ->
								// Authorize
								this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId)
										.switchIfEmpty(Mono.error(() -> new IllegalArgumentException(
												"Could not find ClientRegistration with id '" + clientRegistrationId + "'")))
										.flatMap(clientRegistration -> authorizationContext(authorizeRequest, clientRegistration))
										.flatMap(authorizationContext -> authorize(authorizationContext, principal, serverWebExchange))
										.subscriberContext(context)
								)
						));
	}

	private Mono<OAuth2AuthorizedClient> loadAuthorizedClient(String clientRegistrationId, Authentication principal, ServerWebExchange serverWebExchange) {
		return this.authorizedClientRepository.loadAuthorizedClient(clientRegistrationId, principal, serverWebExchange);
	}

	/**
	 * Performs authorization, and notifies either the {@link #authorizationSuccessHandler}
	 * or {@link #authorizationFailureHandler}, depending on the authorization result.
	 *
	 * @param authorizationContext the context to authorize
	 * @param principal the principle to authorize
	 * @param serverWebExchange the currently active exchange
	 * @return a {@link Mono} that emits the authorized client after the authorization attempt succeeds
	 *         and the {@link #authorizationSuccessHandler} has completed,
	 *         or completes with an exception after the authorization attempt fails
	 *         and the {@link #authorizationFailureHandler} has completed
	 */
	private Mono<OAuth2AuthorizedClient> authorize(
			OAuth2AuthorizationContext authorizationContext,
			Authentication principal,
			ServerWebExchange serverWebExchange) {

		return this.authorizedClientProvider.authorize(authorizationContext)
				// Notify the authorizationSuccessHandler of the successful authorization
				.flatMap(authorizedClient -> authorizationSuccessHandler.onAuthorizationSuccess(
								authorizedClient,
								principal,
								createAttributes(serverWebExchange))
						.thenReturn(authorizedClient))
				// Notify the authorizationFailureHandler of the failed authorization
				.onErrorResume(OAuth2AuthorizationException.class, authorizationException -> authorizationFailureHandler.onAuthorizationFailure(
								authorizationException,
								principal,
								createAttributes(serverWebExchange))
						.then(Mono.error(authorizationException)));
	}

	private Map<String, Object> createAttributes(ServerWebExchange serverWebExchange) {
		return Collections.singletonMap(ServerWebExchange.class.getName(), serverWebExchange);
	}

	private Mono<OAuth2AuthorizationContext> authorizationContext(OAuth2AuthorizeRequest authorizeRequest,
																	OAuth2AuthorizedClient authorizedClient) {
		return Mono.just(authorizeRequest)
				.flatMap(this.contextAttributesMapper)
				.map(attrs -> OAuth2AuthorizationContext.withAuthorizedClient(authorizedClient)
						.principal(authorizeRequest.getPrincipal())
						.attributes(attributes -> {
							if (!CollectionUtils.isEmpty(attrs)) {
								attributes.putAll(attrs);
							}
						})
						.build());
	}

	private Mono<OAuth2AuthorizationContext> authorizationContext(OAuth2AuthorizeRequest authorizeRequest,
																	ClientRegistration clientRegistration) {
		return Mono.just(authorizeRequest)
				.flatMap(this.contextAttributesMapper)
				.map(attrs -> OAuth2AuthorizationContext.withClientRegistration(clientRegistration)
						.principal(authorizeRequest.getPrincipal())
						.attributes(attributes -> {
							if (!CollectionUtils.isEmpty(attrs)) {
								attributes.putAll(attrs);
							}
						})
						.build());
	}

	/**
	 * Sets the {@link ReactiveOAuth2AuthorizedClientProvider} used for authorizing (or re-authorizing) an OAuth 2.0 Client.
	 *
	 * @param authorizedClientProvider the {@link ReactiveOAuth2AuthorizedClientProvider} used for authorizing (or re-authorizing) an OAuth 2.0 Client
	 */
	public void setAuthorizedClientProvider(ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider) {
		Assert.notNull(authorizedClientProvider, "authorizedClientProvider cannot be null");
		this.authorizedClientProvider = authorizedClientProvider;
	}

	/**
	 * Sets the {@code Function} used for mapping attribute(s) from the {@link OAuth2AuthorizeRequest} to a {@code Map} of attributes
	 * to be associated to the {@link OAuth2AuthorizationContext#getAttributes() authorization context}.
	 *
	 * @param contextAttributesMapper the {@code Function} used for supplying the {@code Map} of attributes
	 *                                   to the {@link OAuth2AuthorizationContext#getAttributes() authorization context}
	 */
	public void setContextAttributesMapper(Function<OAuth2AuthorizeRequest, Mono<Map<String, Object>>> contextAttributesMapper) {
		Assert.notNull(contextAttributesMapper, "contextAttributesMapper cannot be null");
		this.contextAttributesMapper = contextAttributesMapper;
	}

	/**
	 * Sets the handler that handles successful authorizations.
	 *
	 * <p>A {@link SaveAuthorizedClientReactiveOAuth2AuthorizationSuccessHandler}
	 * is used by default.</p>
	 *
	 * @param authorizationSuccessHandler the handler that handles successful authorizations.
	 * @see SaveAuthorizedClientReactiveOAuth2AuthorizationSuccessHandler
	 * @since 5.3
	 */
	public void setAuthorizationSuccessHandler(ReactiveOAuth2AuthorizationSuccessHandler authorizationSuccessHandler) {
		Assert.notNull(authorizationSuccessHandler, "authorizationSuccessHandler cannot be null");
		this.authorizationSuccessHandler = authorizationSuccessHandler;
	}

	/**
	 * Sets the handler that handles authorization failures.
	 *
	 * <p>A {@link RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler}
	 * is used by default.</p>
	 *
	 * @param authorizationFailureHandler the handler that handles authorization failures.
	 * @see RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler
	 * @since 5.3
	 */
	public void setAuthorizationFailureHandler(ReactiveOAuth2AuthorizationFailureHandler authorizationFailureHandler) {
		Assert.notNull(authorizationFailureHandler, "authorizationFailureHandler cannot be null");
		this.authorizationFailureHandler = authorizationFailureHandler;
	}

	/**
	 * The default implementation of the {@link #setContextAttributesMapper(Function) contextAttributesMapper}.
	 */
	public static class DefaultContextAttributesMapper implements Function<OAuth2AuthorizeRequest, Mono<Map<String, Object>>> {

		@Override
		public Mono<Map<String, Object>> apply(OAuth2AuthorizeRequest authorizeRequest) {
			ServerWebExchange serverWebExchange = authorizeRequest.getAttribute(ServerWebExchange.class.getName());
			return Mono.justOrEmpty(serverWebExchange)
					.switchIfEmpty(currentServerWebExchangeMono)
					.flatMap(exchange -> {
						Map<String, Object> contextAttributes = Collections.emptyMap();
						String scope = exchange.getRequest().getQueryParams().getFirst(OAuth2ParameterNames.SCOPE);
						if (StringUtils.hasText(scope)) {
							contextAttributes = new HashMap<>();
							contextAttributes.put(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME,
									StringUtils.delimitedListToStringArray(scope, " "));
						}
						return Mono.just(contextAttributes);
					})
					.defaultIfEmpty(Collections.emptyMap());
		}
	}

}
