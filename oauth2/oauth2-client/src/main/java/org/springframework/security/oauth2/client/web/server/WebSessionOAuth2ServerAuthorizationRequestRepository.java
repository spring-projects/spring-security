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
 * @since 5.1
 * @see AuthorizationRequestRepository
 * @see OAuth2AuthorizationRequest
 */
public final class WebSessionOAuth2ServerAuthorizationRequestRepository
		implements ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {

	private static final String DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME = WebSessionOAuth2ServerAuthorizationRequestRepository.class
			.getName() + ".AUTHORIZATION_REQUEST";

	private final String sessionAttributeName = DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME;

	@Override
	public Mono<OAuth2AuthorizationRequest> loadAuthorizationRequest(ServerWebExchange exchange) {
		String state = getStateParameter(exchange);
		if (state == null) {
			return Mono.empty();
		}
		return getStateToAuthorizationRequest(exchange)
				.filter((stateToAuthorizationRequest) -> stateToAuthorizationRequest.containsKey(state))
				.map((stateToAuthorizationRequest) -> stateToAuthorizationRequest.get(state));
	}

	@Override
	public Mono<Void> saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest,
			ServerWebExchange exchange) {
		Assert.notNull(authorizationRequest, "authorizationRequest cannot be null");
		return saveStateToAuthorizationRequest(exchange)
				.doOnNext((stateToAuthorizationRequest) -> stateToAuthorizationRequest
						.put(authorizationRequest.getState(), authorizationRequest))
				.then();
	}

	@Override
	public Mono<OAuth2AuthorizationRequest> removeAuthorizationRequest(ServerWebExchange exchange) {
		String state = getStateParameter(exchange);
		if (state == null) {
			return Mono.empty();
		}
		return exchange.getSession().map(WebSession::getAttributes).handle((sessionAttrs, sink) -> {
			Map<String, OAuth2AuthorizationRequest> stateToAuthzRequest = sessionAttrsMapStateToAuthorizationRequest(
					sessionAttrs);
			if (stateToAuthzRequest == null) {
				sink.complete();
				return;
			}
			OAuth2AuthorizationRequest removedValue = stateToAuthzRequest.remove(state);
			if (stateToAuthzRequest.isEmpty()) {
				sessionAttrs.remove(this.sessionAttributeName);
			}
			else if (removedValue != null) {
				// gh-7327 Overwrite the existing Map to ensure the state is saved for
				// distributed sessions
				sessionAttrs.put(this.sessionAttributeName, stateToAuthzRequest);
			}
			if (removedValue == null) {
				sink.complete();
			}
			else {
				sink.next(removedValue);
			}
		});
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

	private Mono<Map<String, OAuth2AuthorizationRequest>> getStateToAuthorizationRequest(ServerWebExchange exchange) {
		Assert.notNull(exchange, "exchange cannot be null");

		return getSessionAttributes(exchange).flatMap(
				(sessionAttrs) -> Mono.justOrEmpty(this.sessionAttrsMapStateToAuthorizationRequest(sessionAttrs)));
	}

	private Mono<Map<String, OAuth2AuthorizationRequest>> saveStateToAuthorizationRequest(ServerWebExchange exchange) {
		Assert.notNull(exchange, "exchange cannot be null");

		return getSessionAttributes(exchange).doOnNext((sessionAttrs) -> {
			Object stateToAuthzRequest = sessionAttrs.get(this.sessionAttributeName);

			if (stateToAuthzRequest == null) {
				stateToAuthzRequest = new HashMap<String, OAuth2AuthorizationRequest>();
			}

			// No matter stateToAuthzRequest was in session or not, we should always put
			// it into session again
			// in case of redis or hazelcast session. #6215
			sessionAttrs.put(this.sessionAttributeName, stateToAuthzRequest);
		}).flatMap((sessionAttrs) -> Mono.justOrEmpty(this.sessionAttrsMapStateToAuthorizationRequest(sessionAttrs)));
	}

	private Map<String, OAuth2AuthorizationRequest> sessionAttrsMapStateToAuthorizationRequest(
			Map<String, Object> sessionAttrs) {
		return (Map<String, OAuth2AuthorizationRequest>) sessionAttrs.get(this.sessionAttributeName);
	}

}
