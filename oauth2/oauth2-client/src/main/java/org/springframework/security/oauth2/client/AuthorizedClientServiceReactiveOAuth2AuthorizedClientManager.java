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

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.Map;
import java.util.function.Function;

/**
 * An implementation of an {@link ReactiveOAuth2AuthorizedClientManager}
 * that is capable of operating outside of a {@code ServerHttpRequest} context,
 * e.g. in a scheduled/background thread and/or in the service-tier.
 *
 * <p>This is a reactive equivalent of {@link org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager}</p>
 *
 * @author Ankur Pathak
 * @author Phil Clay
 * @see ReactiveOAuth2AuthorizedClientManager
 * @see ReactiveOAuth2AuthorizedClientProvider
 * @see ReactiveOAuth2AuthorizedClientService
 * @since 5.2.2
 */
public final class AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager
		implements ReactiveOAuth2AuthorizedClientManager {

	private final ReactiveClientRegistrationRepository clientRegistrationRepository;
	private final ReactiveOAuth2AuthorizedClientService authorizedClientService;
	private ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = context -> Mono.empty();
	private Function<OAuth2AuthorizeRequest, Mono<Map<String, Object>>> contextAttributesMapper = new DefaultContextAttributesMapper();

	/**
	 * Constructs an {@code AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager} using the provided parameters.
	 *
	 * @param clientRegistrationRepository the repository of client registrations
	 * @param authorizedClientService      the authorized client service
	 */
	public AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(
			ReactiveClientRegistrationRepository clientRegistrationRepository,
			ReactiveOAuth2AuthorizedClientService authorizedClientService) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientService, "authorizedClientService cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientService = authorizedClientService;
	}

	@Override
	public Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizeRequest authorizeRequest) {
		Assert.notNull(authorizeRequest, "authorizeRequest cannot be null");

		return createAuthorizationContext(authorizeRequest)
				.flatMap(this::authorizeAndSave);
	}

	private Mono<OAuth2AuthorizationContext> createAuthorizationContext(OAuth2AuthorizeRequest authorizeRequest) {
		String clientRegistrationId = authorizeRequest.getClientRegistrationId();
		Authentication principal = authorizeRequest.getPrincipal();
		return Mono.justOrEmpty(authorizeRequest.getAuthorizedClient())
				.map(OAuth2AuthorizationContext::withAuthorizedClient)
				.switchIfEmpty(Mono.defer(() -> this.clientRegistrationRepository.findByRegistrationId(clientRegistrationId)
						.flatMap(clientRegistration -> this.authorizedClientService.loadAuthorizedClient(clientRegistrationId, principal.getName())
								.map(OAuth2AuthorizationContext::withAuthorizedClient)
								.switchIfEmpty(Mono.fromSupplier(() -> OAuth2AuthorizationContext.withClientRegistration(clientRegistration))))
						.switchIfEmpty(Mono.error(() -> new IllegalArgumentException("Could not find ClientRegistration with id '" + clientRegistrationId + "'")))))
				.flatMap(contextBuilder -> this.contextAttributesMapper.apply(authorizeRequest)
						.defaultIfEmpty(Collections.emptyMap())
						.map(contextAttributes -> {
							OAuth2AuthorizationContext.Builder builder = contextBuilder.principal(principal);
							if (!contextAttributes.isEmpty()) {
								builder = builder.attributes(attributes -> attributes.putAll(contextAttributes));
							}
							return builder.build();
						}));
	}

	private Mono<OAuth2AuthorizedClient> authorizeAndSave(OAuth2AuthorizationContext authorizationContext) {
		return this.authorizedClientProvider.authorize(authorizationContext)
				.flatMap(authorizedClient -> this.authorizedClientService.saveAuthorizedClient(
								authorizedClient,
								authorizationContext.getPrincipal())
						.thenReturn(authorizedClient))
				.switchIfEmpty(Mono.defer(()-> Mono.justOrEmpty(authorizationContext.getAuthorizedClient())));
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

	/**
	 * The default implementation of the {@link #setContextAttributesMapper(Function) contextAttributesMapper}.
	 */
	public static class DefaultContextAttributesMapper implements Function<OAuth2AuthorizeRequest, Mono<Map<String, Object>>> {

		private final AuthorizedClientServiceOAuth2AuthorizedClientManager.DefaultContextAttributesMapper mapper =
				new AuthorizedClientServiceOAuth2AuthorizedClientManager.DefaultContextAttributesMapper();

		@Override
		public Mono<Map<String, Object>> apply(OAuth2AuthorizeRequest authorizeRequest) {
			return Mono.fromCallable(() -> mapper.apply(authorizeRequest));
		}
	}
}
