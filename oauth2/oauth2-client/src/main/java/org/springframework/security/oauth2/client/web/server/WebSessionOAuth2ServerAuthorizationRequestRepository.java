/*
 * Copyright 2002-2021 the original author or authors.
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

import java.util.HashMap;
import java.util.Map;

import reactor.core.publisher.Mono;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;

/**
 * An implementation of an {@link ServerAuthorizationRequestRepository} that stores
 * {@link OAuth2AuthorizationRequest} in the {@code WebSession}.
 *
 * @author Rob Winch
 * @author Steve Riesenberg
 * @since 5.1
 * @see AuthorizationRequestRepository
 * @see OAuth2AuthorizationRequest
 */
public final class WebSessionOAuth2ServerAuthorizationRequestRepository
		implements ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {

	private static final String DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME = WebSessionOAuth2ServerAuthorizationRequestRepository.class
			.getName() + ".AUTHORIZATION_REQUEST";

	private final String sessionAttributeName = DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME;

	private boolean allowMultipleAuthorizationRequests;

	@Override
	public Mono<OAuth2AuthorizationRequest> loadAuthorizationRequest(ServerWebExchange exchange) {
		String state = getStateParameter(exchange);
		if (state == null) {
			return Mono.empty();
		}
		// @formatter:off
		return this.getSessionAttributes(exchange)
				.filter((sessionAttrs) -> sessionAttrs.containsKey(this.sessionAttributeName))
				.map(this::getAuthorizationRequests)
				.filter((stateToAuthorizationRequest) -> stateToAuthorizationRequest.containsKey(state))
				.map((stateToAuthorizationRequest) -> stateToAuthorizationRequest.get(state));
		// @formatter:on
	}

	@Override
	public Mono<Void> saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest,
			ServerWebExchange exchange) {
		Assert.notNull(authorizationRequest, "authorizationRequest cannot be null");
		Assert.notNull(exchange, "exchange cannot be null");
		// @formatter:off
		return getSessionAttributes(exchange)
				.doOnNext((sessionAttrs) -> {
					if (this.allowMultipleAuthorizationRequests) {
						Map<String, OAuth2AuthorizationRequest> authorizationRequests = this.getAuthorizationRequests(
								sessionAttrs);
						authorizationRequests.put(authorizationRequest.getState(), authorizationRequest);
						sessionAttrs.put(this.sessionAttributeName, authorizationRequests);
					}
					else {
						sessionAttrs.put(this.sessionAttributeName, authorizationRequest);
					}
				})
				.then();
		// @formatter:on
	}

	@Override
	public Mono<OAuth2AuthorizationRequest> removeAuthorizationRequest(ServerWebExchange exchange) {
		String state = getStateParameter(exchange);
		if (state == null) {
			return Mono.empty();
		}
		// @formatter:off
		return getSessionAttributes(exchange)
				.flatMap((sessionAttrs) -> {
					Map<String, OAuth2AuthorizationRequest> authorizationRequests = this.getAuthorizationRequests(
							sessionAttrs);
					OAuth2AuthorizationRequest originalRequest = authorizationRequests.remove(state);
					if (authorizationRequests.isEmpty()) {
						sessionAttrs.remove(this.sessionAttributeName);
					}
					else if (authorizationRequests.size() == 1) {
						sessionAttrs.put(this.sessionAttributeName, authorizationRequests.values().iterator().next());
					}
					else {
						sessionAttrs.put(this.sessionAttributeName, authorizationRequests);
					}
					return Mono.justOrEmpty(originalRequest);
				});
		// @formatter:on
	}

	/**
	 * Gets the state parameter from the {@link ServerHttpRequest}
	 * @param exchange the exchange to use
	 * @return the state parameter or null if not found
	 */
	private String getStateParameter(ServerWebExchange exchange) {
		Assert.notNull(exchange, "exchange cannot be null");
		return exchange.getRequest().getQueryParams().getFirst(OAuth2ParameterNames.STATE);
	}

	private Mono<Map<String, Object>> getSessionAttributes(ServerWebExchange exchange) {
		return exchange.getSession().map(WebSession::getAttributes);
	}

	private Map<String, OAuth2AuthorizationRequest> getAuthorizationRequests(Map<String, Object> sessionAttrs) {
		Object sessionAttributeValue = sessionAttrs.get(this.sessionAttributeName);
		if (sessionAttributeValue == null) {
			return new HashMap<>();
		}
		else if (sessionAttributeValue instanceof OAuth2AuthorizationRequest) {
			OAuth2AuthorizationRequest oauth2AuthorizationRequest = (OAuth2AuthorizationRequest) sessionAttributeValue;
			Map<String, OAuth2AuthorizationRequest> authorizationRequests = new HashMap<>(1);
			authorizationRequests.put(oauth2AuthorizationRequest.getState(), oauth2AuthorizationRequest);
			return authorizationRequests;
		}
		else if (sessionAttributeValue instanceof Map) {
			@SuppressWarnings("unchecked")
			Map<String, OAuth2AuthorizationRequest> authorizationRequests = (Map<String, OAuth2AuthorizationRequest>) sessionAttrs
					.get(this.sessionAttributeName);
			return authorizationRequests;
		}
		else {
			throw new IllegalStateException(
					"authorizationRequests is supposed to be a Map or OAuth2AuthorizationRequest but actually is a "
							+ sessionAttributeValue.getClass());
		}
	}

	/**
	 * Configure if multiple {@link OAuth2AuthorizationRequest}s should be stored per
	 * session. Default is false (not allow multiple {@link OAuth2AuthorizationRequest}
	 * per session).
	 * @param allowMultipleAuthorizationRequests true allows more than one
	 * {@link OAuth2AuthorizationRequest} to be stored per session.
	 * @since 5.5
	 */
	@Deprecated
	public void setAllowMultipleAuthorizationRequests(boolean allowMultipleAuthorizationRequests) {
		this.allowMultipleAuthorizationRequests = allowMultipleAuthorizationRequests;
	}

}
