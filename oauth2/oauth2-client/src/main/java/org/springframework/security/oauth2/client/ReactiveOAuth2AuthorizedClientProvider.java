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

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import reactor.core.publisher.Mono;

/**
 * A strategy for authorizing (or re-authorizing) an OAuth 2.0 Client.
 * Implementations will typically implement a specific {@link AuthorizationGrantType authorization grant} type.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see OAuth2AuthorizedClient
 * @see OAuth2AuthorizationContext
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-1.3">Section 1.3 Authorization Grant</a>
 */
public interface ReactiveOAuth2AuthorizedClientProvider {

	/**
	 * Attempt to authorize (or re-authorize) the {@link OAuth2AuthorizationContext#getClientRegistration() client} in the provided context.
	 * Implementations must return an empty {@code Mono} if authorization is not supported for the specified client,
	 * e.g. the provider doesn't support the {@link ClientRegistration#getAuthorizationGrantType() authorization grant} type configured for the client.
	 *
	 * @param context the context that holds authorization-specific state for the client
	 * @return the {@link OAuth2AuthorizedClient} or an empty {@code Mono} if authorization is not supported for the specified client
	 */
	Mono<OAuth2AuthorizedClient> authorize(OAuth2AuthorizationContext context);

}
