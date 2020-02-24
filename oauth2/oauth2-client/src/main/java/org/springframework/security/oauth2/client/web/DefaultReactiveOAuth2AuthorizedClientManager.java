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
package org.springframework.security.oauth2.client.web;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
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
 * The default implementation of a {@link ReactiveOAuth2AuthorizedClientManager}.
 *
 * @author Joe Grandja
 * @author OGAWA, Takeshi
 * @since 5.2
 * @see ReactiveOAuth2AuthorizedClientManager
 * @see ReactiveOAuth2AuthorizedClientProvider
 */
public final class DefaultReactiveOAuth2AuthorizedClientManager implements ReactiveOAuth2AuthorizedClientManager {
	private final ReactiveClientRegistrationRepository clientRegistrationRepository;
	private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
	private ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = context -> Mono.empty();
	private Function<OAuth2AuthorizeRequest, Mono<Map<String, Object>>> contextAttributesMapper = new DefaultContextAttributesMapper();

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
	}

	@Override
	public Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizeRequest authorizeRequest) {
		Assert.notNull(authorizeRequest, "authorizeRequest cannot be null");

		String clientRegistrationId = authorizeRequest.getClientRegistrationId();
		Authentication principal = authorizeRequest.getPrincipal();
		ServerWebExchange serverWebExchange = authorizeRequest.getAttribute(ServerWebExchange.class.getName());

		return Mono.justOrEmpty(authorizeRequest.getAuthorizedClient())
				.switchIfEmpty(Mono.defer(() -> loadAuthorizedClient(clientRegistrationId, principal, serverWebExchange)))
				.flatMap(authorizedClient -> {
					// Re-authorize
					return authorizationContext(authorizeRequest, authorizedClient)
							.flatMap(this.authorizedClientProvider::authorize)
							.flatMap(reauthorizedClient -> saveAuthorizedClient(reauthorizedClient, principal, serverWebExchange))
							// Default to the existing authorizedClient if the client was not re-authorized
							.defaultIfEmpty(authorizeRequest.getAuthorizedClient() != null ?
									authorizeRequest.getAuthorizedClient() : authorizedClient)
							// If the refresh token fails, get the token again
							.onErrorResume(OAuth2AuthorizationException.class, (ex) -> Mono.empty());
				})
				.switchIfEmpty(Mono.deferWithContext(context ->
						// Authorize
						this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId)
								.switchIfEmpty(Mono.error(() -> new IllegalArgumentException(
										"Could not find ClientRegistration with id '" + clientRegistrationId + "'")))
								.flatMap(clientRegistration -> authorizationContext(authorizeRequest, clientRegistration))
								.flatMap(this.authorizedClientProvider::authorize)
								.flatMap(authorizedClient -> saveAuthorizedClient(authorizedClient, principal, serverWebExchange))
								.subscriberContext(context)
						)
				);
	}

	private Mono<OAuth2AuthorizedClient> loadAuthorizedClient(String clientRegistrationId, Authentication principal, ServerWebExchange serverWebExchange) {
		return Mono.justOrEmpty(serverWebExchange)
				.switchIfEmpty(Mono.defer(() -> currentServerWebExchange()))
				.switchIfEmpty(Mono.error(() -> new IllegalArgumentException("serverWebExchange cannot be null")))
				.flatMap(exchange -> this.authorizedClientRepository.loadAuthorizedClient(clientRegistrationId, principal, exchange));
	}

	private Mono<OAuth2AuthorizedClient> saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal, ServerWebExchange serverWebExchange) {
		return Mono.justOrEmpty(serverWebExchange)
				.switchIfEmpty(Mono.defer(() -> currentServerWebExchange()))
				.switchIfEmpty(Mono.error(() -> new IllegalArgumentException("serverWebExchange cannot be null")))
				.flatMap(exchange -> this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, principal, exchange)
						.thenReturn(authorizedClient));
	}

	private static Mono<ServerWebExchange> currentServerWebExchange() {
		return Mono.subscriberContext()
				.filter(c -> c.hasKey(ServerWebExchange.class))
				.map(c -> c.get(ServerWebExchange.class));
	}

	private Mono<OAuth2AuthorizationContext> authorizationContext(OAuth2AuthorizeRequest authorizeRequest,
																	OAuth2AuthorizedClient authorizedClient) {
		return Mono.just(authorizeRequest)
				.flatMap(this.contextAttributesMapper::apply)
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
				.flatMap(this.contextAttributesMapper::apply)
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
	 * The default implementation of the {@link #setContextAttributesMapper(Function) contextAttributesMapper}.
	 */
	public static class DefaultContextAttributesMapper implements Function<OAuth2AuthorizeRequest, Mono<Map<String, Object>>> {

		@Override
		public Mono<Map<String, Object>> apply(OAuth2AuthorizeRequest authorizeRequest) {
			ServerWebExchange serverWebExchange = authorizeRequest.getAttribute(ServerWebExchange.class.getName());
			return Mono.justOrEmpty(serverWebExchange)
					.switchIfEmpty(Mono.defer(() -> currentServerWebExchange()))
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
