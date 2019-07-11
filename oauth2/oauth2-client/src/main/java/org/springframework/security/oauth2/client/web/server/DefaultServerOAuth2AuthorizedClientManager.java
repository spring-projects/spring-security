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
package org.springframework.security.oauth2.client.web.server;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * The default implementation of a {@link ServerOAuth2AuthorizedClientManager}.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see ServerOAuth2AuthorizedClientManager
 * @see ReactiveOAuth2AuthorizedClientProvider
 */
public final class DefaultServerOAuth2AuthorizedClientManager implements ServerOAuth2AuthorizedClientManager {
	private final ReactiveClientRegistrationRepository clientRegistrationRepository;
	private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
	private ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = context -> Mono.empty();
	private Function<ServerOAuth2AuthorizeRequest, Map<String, Object>> contextAttributesMapper = new DefaultContextAttributesMapper();

	/**
	 * Constructs a {@code DefaultServerOAuth2AuthorizedClientManager} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientRepository the repository of authorized clients
	 */
	public DefaultServerOAuth2AuthorizedClientManager(ReactiveClientRegistrationRepository clientRegistrationRepository,
														ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientRepository = authorizedClientRepository;
	}

	@Override
	public Mono<OAuth2AuthorizedClient> authorize(ServerOAuth2AuthorizeRequest authorizeRequest) {
		Assert.notNull(authorizeRequest, "authorizeRequest cannot be null");

		String clientRegistrationId = authorizeRequest.getClientRegistrationId();
		Authentication principal = authorizeRequest.getPrincipal();
		ServerWebExchange serverWebExchange = authorizeRequest.getServerWebExchange();

		return Mono.justOrEmpty(authorizeRequest.getAuthorizedClient())
				.switchIfEmpty(Mono.defer(() ->
						this.authorizedClientRepository.loadAuthorizedClient(clientRegistrationId, principal, serverWebExchange)))
				.flatMap(authorizedClient -> {
					// Re-authorize
					OAuth2AuthorizationContext reauthorizationContext =
							OAuth2AuthorizationContext.withAuthorizedClient(authorizedClient)
									.principal(principal)
									.attributes(this.contextAttributesMapper.apply(authorizeRequest))
									.build();
					return Mono.just(reauthorizationContext)
							.flatMap(this.authorizedClientProvider::authorize)
							.doOnNext(reauthorizedClient ->
									this.authorizedClientRepository.saveAuthorizedClient(
											reauthorizedClient, principal, serverWebExchange))
							// Return the `authorizedClient` if `reauthorizedClient` is null, e.g. re-authorization is not supported
							.defaultIfEmpty(authorizedClient);
				})
				.switchIfEmpty(Mono.defer(() ->
						// Authorize
						this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId)
								.switchIfEmpty(Mono.error(() -> new IllegalArgumentException(
										"Could not find ClientRegistration with id '" + clientRegistrationId + "'")))
								.map(clientRegistration -> OAuth2AuthorizationContext.withClientRegistration(clientRegistration)
										.principal(principal)
										.attributes(this.contextAttributesMapper.apply(authorizeRequest))
										.build())
								.flatMap(this.authorizedClientProvider::authorize)
								.doOnNext(authorizedClient ->
										this.authorizedClientRepository.saveAuthorizedClient(
												authorizedClient, principal, serverWebExchange))
				));
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
	 * Sets the {@code Function} used for mapping attribute(s) from the {@link ServerOAuth2AuthorizeRequest} to a {@code Map} of attributes
	 * to be associated to the {@link OAuth2AuthorizationContext#getAttributes() authorization context}.
	 *
	 * @param contextAttributesMapper the {@code Function} used for supplying the {@code Map} of attributes
	 *                                   to the {@link OAuth2AuthorizationContext#getAttributes() authorization context}
	 */
	public void setContextAttributesMapper(Function<ServerOAuth2AuthorizeRequest, Map<String, Object>> contextAttributesMapper) {
		Assert.notNull(contextAttributesMapper, "contextAttributesMapper cannot be null");
		this.contextAttributesMapper = contextAttributesMapper;
	}

	/**
	 * The default implementation of the {@link #setContextAttributesMapper(Function) contextAttributesMapper}.
	 */
	public static class DefaultContextAttributesMapper implements Function<ServerOAuth2AuthorizeRequest, Map<String, Object>> {

		@Override
		public Map<String, Object> apply(ServerOAuth2AuthorizeRequest authorizeRequest) {
			Map<String, Object> contextAttributes = Collections.emptyMap();
			String scope = authorizeRequest.getServerWebExchange().getRequest().getQueryParams().getFirst(OAuth2ParameterNames.SCOPE);
			if (StringUtils.hasText(scope)) {
				contextAttributes = new HashMap<>();
				contextAttributes.put(OAuth2AuthorizationContext.REQUEST_SCOPE_ATTRIBUTE_NAME,
						StringUtils.delimitedListToStringArray(scope, " "));
			}
			return contextAttributes;
		}
	}
}
