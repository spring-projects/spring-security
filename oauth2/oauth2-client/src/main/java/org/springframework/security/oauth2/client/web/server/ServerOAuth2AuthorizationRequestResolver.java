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

import reactor.core.publisher.Mono;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.server.ServerWebExchange;

/**
 * Implementations of this interface are capable of resolving an
 * {@link OAuth2AuthorizationRequest} from the provided {@code ServerWebExchange}. Used by
 * the {@link OAuth2AuthorizationRequestRedirectWebFilter} for resolving Authorization
 * Requests.
 *
 * @author Rob Winch
 * @since 5.1
 * @see OAuth2AuthorizationRequest
 * @see OAuth2AuthorizationRequestRedirectWebFilter
 */
public interface ServerOAuth2AuthorizationRequestResolver {

	/**
	 * Returns the {@link OAuth2AuthorizationRequest} resolved from the provided
	 * {@code HttpServletRequest} or {@code null} if not available.
	 * @param exchange the {@code ServerWebExchange}
	 * @return the resolved {@link OAuth2AuthorizationRequest} or {@code null} if not
	 * available
	 */
	Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange);

	/**
	 * Returns the {@link OAuth2AuthorizationRequest} resolved from the provided
	 * {@code HttpServletRequest} or {@code null} if not available.
	 * @param exchange the {@code ServerWebExchange}
	 * @param clientRegistrationId the client registration id
	 * @return the resolved {@link OAuth2AuthorizationRequest} or {@code null} if not
	 * available
	 */
	Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange, String clientRegistrationId);

}
