/*
 * Copyright 2002-2018 the original author or authors.
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

import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * Implementations of this interface are responsible for the persistence of
 * {@link OAuth2AuthorizationRequest} between requests.
 *
 * <p>
 * Used by the {@link OAuth2AuthorizationRequestRedirectFilter} for persisting the
 * Authorization Request before it initiates the authorization code grant flow. As well,
 * used by the {@link OAuth2LoginAuthenticationFilter} for resolving the associated
 * Authorization Request when handling the callback of the Authorization Response.
 *
 * @author Rob Winch
 * @since 5.1
 * @see OAuth2AuthorizationRequest
 * @see HttpSessionOAuth2AuthorizationRequestRepository
 * @param <T> The type of OAuth 2.0 Authorization Request
 */
public interface ServerAuthorizationRequestRepository<T extends OAuth2AuthorizationRequest> {

	/**
	 * Returns the {@link OAuth2AuthorizationRequest} associated to the provided
	 * {@code HttpServletRequest} or {@code null} if not available.
	 * @param exchange the {@code ServerWebExchange}
	 * @return the {@link OAuth2AuthorizationRequest} or {@code null} if not available
	 */
	Mono<T> loadAuthorizationRequest(ServerWebExchange exchange);

	/**
	 * Persists the {@link OAuth2AuthorizationRequest} associating it to the provided
	 * {@code HttpServletRequest} and/or {@code HttpServletResponse}.
	 * @param authorizationRequest the {@link OAuth2AuthorizationRequest}
	 * @param exchange the {@code ServerWebExchange}
	 */
	Mono<Void> saveAuthorizationRequest(T authorizationRequest, ServerWebExchange exchange);

	/**
	 * Removes and returns the {@link OAuth2AuthorizationRequest} associated to the
	 * provided {@code HttpServletRequest} or if not available returns {@code null}.
	 * @param exchange the {@code ServerWebExchange}
	 * @return the removed {@link OAuth2AuthorizationRequest} or {@code null} if not
	 * available
	 */
	Mono<T> removeAuthorizationRequest(ServerWebExchange exchange);

}
