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
package org.springframework.security.oauth2.client;

import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * An implementation of a {@link ReactiveOAuth2AuthorizedClientManager} that is capable of
 * operating outside of the context of a {@link ServerWebExchange}, e.g. in a
 * scheduled/background thread and/or in the service-tier.
 *
 * <p>
 * (When operating <em>within</em> the context of a {@link ServerWebExchange}, use
 * {@link DefaultReactiveOAuth2AuthorizedClientManager} instead.)
 * </p>
 *
 * <p>
 * This is a reactive equivalent of
 * {@link org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager}.
 * </p>
 *
 * <h2>Authorized Client Persistence</h2>
 *
 * <p>
 * This client manager utilizes a {@link ReactiveOAuth2AuthorizedClientService} to persist
 * {@link OAuth2AuthorizedClient}s.
 * </p>
 *
 * <p>
 * By default, when an authorization attempt succeeds, the {@link OAuth2AuthorizedClient}
 * will be saved in the authorized client service. This functionality can be changed by
 * configuring a custom {@link ReactiveOAuth2AuthorizationSuccessHandler} via
 * {@link #setAuthorizationSuccessHandler(ReactiveOAuth2AuthorizationSuccessHandler)}.
 * </p>
 *
 * <p>
 * By default, when an authorization attempt fails due to an
 * {@value org.springframework.security.oauth2.core.OAuth2ErrorCodes#INVALID_GRANT} error,
 * the previously saved {@link OAuth2AuthorizedClient} will be removed from the authorized
 * client service. (The
 * {@value org.springframework.security.oauth2.core.OAuth2ErrorCodes#INVALID_GRANT} error
 * generally occurs when a refresh token that is no longer valid is used to retrieve a new
 * access token.) This functionality can be changed by configuring a custom
 * {@link ReactiveOAuth2AuthorizationFailureHandler} via
 * {@link #setAuthorizationFailureHandler(ReactiveOAuth2AuthorizationFailureHandler)}.
 * </p>
 *
 * @author Ankur Pathak
 * @author Phil Clay
 * @since 5.2.2
 * @see ReactiveOAuth2AuthorizedClientManager
 * @see ReactiveOAuth2AuthorizedClientProvider
 * @see ReactiveOAuth2AuthorizedClientService
 * @see ReactiveOAuth2AuthorizationSuccessHandler
 * @see ReactiveOAuth2AuthorizationFailureHandler
 */
public final class AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager
		implements ReactiveOAuth2AuthorizedClientManager {

	private static final ReactiveOAuth2AuthorizedClientProvider DEFAULT_AUTHORIZED_CLIENT_PROVIDER = ReactiveOAuth2AuthorizedClientProviderBuilder
			.builder().clientCredentials().build();

	private final ReactiveClientRegistrationRepository clientRegistrationRepository;

	private final ReactiveOAuth2AuthorizedClientService authorizedClientService;

	private ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = DEFAULT_AUTHORIZED_CLIENT_PROVIDER;

	private Function<OAuth2AuthorizeRequest, Mono<Map<String, Object>>> contextAttributesMapper = new DefaultContextAttributesMapper();

	private ReactiveOAuth2AuthorizationSuccessHandler authorizationSuccessHandler;

	private ReactiveOAuth2AuthorizationFailureHandler authorizationFailureHandler;

	/**
	 * Constructs an {@code AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager}
	 * using the provided parameters.
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientService the authorized client service
	 */
	public AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			ReactiveOAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientService = authorizedClientService;
		this.authorizationSuccessHandler = (authorizedClient, principal, attributes) -> authorizedClientService
				.saveAuthorizedClient(authorizedClient, principal);
		this.authorizationFailureHandler = new RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler(
				(clientRegistrationId, principal, attributes) -> this.authorizedClientService
						.removeAuthorizedClient(clientRegistrationId, principal.getName()));
	}

	@Override
	public Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizeRequest authorizeRequest) {
		Assert.notNull(authorizeRequest, "authorizeRequest cannot be null");

		return createAuthorizationContext(authorizeRequest)
				.flatMap(authorizationContext -> authorize(authorizationContext, authorizeRequest.getPrincipal()));
	}

	private Mono<OAuth2AuthorizationContext> createAuthorizationContext(OAuth2AuthorizeRequest authorizeRequest) {
		String clientRegistrationId = authorizeRequest.getClientRegistrationId();
		Authentication principal = authorizeRequest.getPrincipal();
		return Mono.justOrEmpty(authorizeRequest.getAuthorizedClient())
				.map(OAuth2AuthorizationContext::withAuthorizedClient)
				.switchIfEmpty(Mono.defer(() -> this.clientRegistrationRepository
						.findByRegistrationId(clientRegistrationId)
						.flatMap(clientRegistration -> this.authorizedClientService
								.loadAuthorizedClient(clientRegistrationId, principal.getName())
								.map(OAuth2AuthorizationContext::withAuthorizedClient)
								.switchIfEmpty(Mono.fromSupplier(
										() -> OAuth2AuthorizationContext.withClientRegistration(clientRegistration))))
						.switchIfEmpty(Mono.error(() -> new IllegalArgumentException(
								"Could not find ClientRegistration with id '" + clientRegistrationId + "'")))))
				.flatMap(contextBuilder -> this.contextAttributesMapper.apply(authorizeRequest)
						.defaultIfEmpty(Collections.emptyMap()).map(contextAttributes -> {
							OAuth2AuthorizationContext.Builder builder = contextBuilder.principal(principal);
							if (!contextAttributes.isEmpty()) {
								builder = builder.attributes(attributes -> attributes.putAll(contextAttributes));
							}
							return builder.build();
						}));
	}

	/**
	 * Performs authorization and then delegates to either the
	 * {@link #authorizationSuccessHandler} or {@link #authorizationFailureHandler},
	 * depending on the authorization result.
	 * @param authorizationContext the context to authorize
	 * @param principal the principle to authorize
	 * @return a {@link Mono} that emits the authorized client after the authorization
	 * attempt succeeds and the {@link #authorizationSuccessHandler} has completed, or
	 * completes with an exception after the authorization attempt fails and the
	 * {@link #authorizationFailureHandler} has completed
	 */
	private Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizationContext authorizationContext,
			Authentication principal) {
		return this.authorizedClientProvider.authorize(authorizationContext)
				// Delegate to the authorizationSuccessHandler of the successful
				// authorization
				.flatMap(authorizedClient -> this.authorizationSuccessHandler
						.onAuthorizationSuccess(authorizedClient, principal, Collections.emptyMap())
						.thenReturn(authorizedClient))
				// Delegate to the authorizationFailureHandler of the failed authorization
				.onErrorResume(OAuth2AuthorizationException.class,
						authorizationException -> this.authorizationFailureHandler
								.onAuthorizationFailure(authorizationException, principal, Collections.emptyMap())
								.then(Mono.error(authorizationException)))
				.switchIfEmpty(Mono.defer(() -> Mono.justOrEmpty(authorizationContext.getAuthorizedClient())));
	}

	/**
	 * Sets the {@link ReactiveOAuth2AuthorizedClientProvider} used for authorizing (or
	 * re-authorizing) an OAuth 2.0 Client.
	 * @param authorizedClientProvider the {@link ReactiveOAuth2AuthorizedClientProvider}
	 * used for authorizing (or re-authorizing) an OAuth 2.0 Client
	 */
	public void setAuthorizedClientProvider(ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider) {
		Assert.notNull(authorizedClientProvider, "authorizedClientProvider cannot be null");
		this.authorizedClientProvider = authorizedClientProvider;
	}

	/**
	 * Sets the {@code Function} used for mapping attribute(s) from the
	 * {@link OAuth2AuthorizeRequest} to a {@code Map} of attributes to be associated to
	 * the {@link OAuth2AuthorizationContext#getAttributes() authorization context}.
	 * @param contextAttributesMapper the {@code Function} used for supplying the
	 * {@code Map} of attributes to the {@link OAuth2AuthorizationContext#getAttributes()
	 * authorization context}
	 */
	public void setContextAttributesMapper(
			Function<OAuth2AuthorizeRequest, Mono<Map<String, Object>>> contextAttributesMapper) {
		Assert.notNull(contextAttributesMapper, "contextAttributesMapper cannot be null");
		this.contextAttributesMapper = contextAttributesMapper;
	}

	/**
	 * Sets the handler that handles successful authorizations.
	 *
	 * The default saves {@link OAuth2AuthorizedClient}s in the
	 * {@link ReactiveOAuth2AuthorizedClientService}.
	 * @param authorizationSuccessHandler the handler that handles successful
	 * authorizations.
	 * @since 5.3
	 */
	public void setAuthorizationSuccessHandler(ReactiveOAuth2AuthorizationSuccessHandler authorizationSuccessHandler) {
		Assert.notNull(authorizationSuccessHandler, "authorizationSuccessHandler cannot be null");
		this.authorizationSuccessHandler = authorizationSuccessHandler;
	}

	/**
	 * Sets the handler that handles authorization failures.
	 *
	 * <p>
	 * A {@link RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler} is used
	 * by default.
	 * </p>
	 * @param authorizationFailureHandler the handler that handles authorization failures.
	 * @since 5.3
	 * @see RemoveAuthorizedClientReactiveOAuth2AuthorizationFailureHandler
	 */
	public void setAuthorizationFailureHandler(ReactiveOAuth2AuthorizationFailureHandler authorizationFailureHandler) {
		Assert.notNull(authorizationFailureHandler, "authorizationFailureHandler cannot be null");
		this.authorizationFailureHandler = authorizationFailureHandler;
	}

	/**
	 * The default implementation of the {@link #setContextAttributesMapper(Function)
	 * contextAttributesMapper}.
	 */
	public static class DefaultContextAttributesMapper
			implements Function<OAuth2AuthorizeRequest, Mono<Map<String, Object>>> {

		private final AuthorizedClientServiceOAuth2AuthorizedClientManager.DefaultContextAttributesMapper mapper = new AuthorizedClientServiceOAuth2AuthorizedClientManager.DefaultContextAttributesMapper();

		@Override
		public Mono<Map<String, Object>> apply(OAuth2AuthorizeRequest authorizeRequest) {
			return Mono.fromCallable(() -> this.mapper.apply(authorizeRequest));
		}

	}

}
