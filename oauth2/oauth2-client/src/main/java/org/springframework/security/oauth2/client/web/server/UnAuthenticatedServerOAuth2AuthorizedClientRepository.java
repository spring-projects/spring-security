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

package org.springframework.security.oauth2.client.web.server;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Provides support for an unauthenticated user. This is useful when running as a process
 * with no user associated to it. The implementation ensures that
 * {@link ServerWebExchange} is null and that the {@link Authentication} is either null or
 * anonymous to prevent using it incorrectly.
 *
 * @deprecated Use {@link AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager}
 * instead
 * @author Rob Winch
 * @since 5.1
 */
@Deprecated
public class UnAuthenticatedServerOAuth2AuthorizedClientRepository implements ServerOAuth2AuthorizedClientRepository {

	private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	private final Map<String, OAuth2AuthorizedClient> clientRegistrationIdToAuthorizedClient = new ConcurrentHashMap<>();

	@Override
	public <T extends OAuth2AuthorizedClient> Mono<T> loadAuthorizedClient(String clientRegistrationId,
			Authentication authentication, ServerWebExchange serverWebExchange) {
		Assert.notNull(clientRegistrationId, "clientRegistrationId cannot be null");
		Assert.isNull(serverWebExchange, "serverWebExchange must be null");
		Assert.isTrue(isUnauthenticated(authentication), "The user " + authentication + " should not be authenticated");

		return Mono.fromSupplier(() -> (T) this.clientRegistrationIdToAuthorizedClient.get(clientRegistrationId));
	}

	@Override
	public Mono<Void> saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication authentication,
			ServerWebExchange serverWebExchange) {
		Assert.notNull(authorizedClient, "authorizedClient cannot be null");
		Assert.isNull(serverWebExchange, "serverWebExchange must be null");
		Assert.isTrue(isUnauthenticated(authentication), "The user " + authentication + " should not be authenticated");
		return Mono.fromRunnable(() -> {
			String clientRegistrationId = authorizedClient.getClientRegistration().getRegistrationId();
			this.clientRegistrationIdToAuthorizedClient.put(clientRegistrationId, authorizedClient);
		});
	}

	@Override
	public Mono<Void> removeAuthorizedClient(String clientRegistrationId, Authentication authentication,
			ServerWebExchange serverWebExchange) {
		Assert.notNull(clientRegistrationId, "clientRegistrationId cannot be null");
		Assert.isNull(serverWebExchange, "serverWebExchange " + serverWebExchange + "must be null");
		Assert.isTrue(isUnauthenticated(authentication), "The user " + authentication + " should not be authenticated");
		return Mono.fromRunnable(() -> this.clientRegistrationIdToAuthorizedClient.remove(clientRegistrationId));
	}

	private boolean isUnauthenticated(Authentication authentication) {
		return authentication == null || this.trustResolver.isAnonymous(authentication);
	}

}
