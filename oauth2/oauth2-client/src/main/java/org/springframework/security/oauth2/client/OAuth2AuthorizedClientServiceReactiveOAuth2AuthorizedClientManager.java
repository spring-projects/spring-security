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
package org.springframework.security.oauth2.client;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * An implementation of an {@link ReactiveOAuth2AuthorizedClientManager}
 * that is capable of operating outside of a {@code ServerHttpRequest} context,
 * e.g. in a scheduled/background thread and/or in the service-tier.
 *
 * @author Ankur Pathak
 * @see ReactiveOAuth2AuthorizedClientManager
 * @see ReactiveOAuth2AuthorizedClientProvider
 * @see ReactiveOAuth2AuthorizedClientService
 * @since 5.3
 */
public final class OAuth2AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager implements ReactiveOAuth2AuthorizedClientManager {
	private final ReactiveClientRegistrationRepository clientRegistrationRepository;
	private final ReactiveOAuth2AuthorizedClientService authorizedClientService;
	private ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = context -> Mono.empty();
	private Function<OAuth2AuthorizeRequest, Mono<Map<String, Object>>> contextAttributesMapper = new DefaultContextAttributesMapper();

	/**
	 * Constructs an {@code OAuth2AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientService      the authorized client service
	 */
	public OAuth2AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(ReactiveClientRegistrationRepository clientRegistrationRepository,
			ReactiveOAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientService = authorizedClientService;
	}

	@Nullable
	@Override
	public Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizeRequest authorizeRequest) {
		Assert.notNull(authorizeRequest, "authorizeRequest cannot be null");
		String clientRegistrationId = authorizeRequest.getClientRegistrationId();
		OAuth2AuthorizedClient authorizedClient = authorizeRequest.getAuthorizedClient();
		Authentication principal = authorizeRequest.getPrincipal();
		// @formatter:off
		return Mono.justOrEmpty(authorizedClient)
				.map(OAuth2AuthorizationContext::withAuthorizedClient)
				.switchIfEmpty(Mono.defer(() -> this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId)
								.flatMap(clientRegistration -> this.authorizedClientService.loadAuthorizedClient(clientRegistrationId, principal.getName())
										.map(OAuth2AuthorizationContext::withAuthorizedClient)
										.switchIfEmpty(Mono.fromSupplier(() -> OAuth2AuthorizationContext.withClientRegistration(clientRegistration)))
								)
								.switchIfEmpty(Mono.error(new IllegalArgumentException("Could not find ClientRegistration with id '" + clientRegistrationId + "'")))
							)
				)
				.flatMap(contextBuilder -> this.contextAttributesMapper.apply(authorizeRequest)
						.filter(contextAttributes-> !CollectionUtils.isEmpty(contextAttributes))
						.map(contextAttributes -> contextBuilder.principal(principal)
								.attributes(attributes -> {
									attributes.putAll(contextAttributes);
								}).build())
				).flatMap(authorizationContext -> this.authorizedClientProvider.authorize(authorizationContext)
						.doOnNext(_authorizedClient -> authorizedClientService.saveAuthorizedClient(_authorizedClient, principal))
						.switchIfEmpty(Mono.defer(()-> Mono.justOrEmpty(Optional.ofNullable(authorizationContext.getAuthorizedClient()))))
				);
		// @formatter:on
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
	 *                                to the {@link OAuth2AuthorizationContext#getAttributes() authorization context}
	 */
	public void setContextAttributesMapper(Function<OAuth2AuthorizeRequest, Mono<Map<String, Object>>> contextAttributesMapper) {
		Assert.notNull(contextAttributesMapper, "contextAttributesMapper cannot be null");
		this.contextAttributesMapper = contextAttributesMapper;
	}

	private static Mono<ServerWebExchange> currentServerWebExchange() {
		return Mono.subscriberContext()
				.filter(c -> c.hasKey(ServerWebExchange.class))
				.map(c -> c.get(ServerWebExchange.class));
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
