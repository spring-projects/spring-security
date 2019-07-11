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

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import reactor.core.publisher.Mono;

/**
 * Implementations of this interface are responsible for the overall management
 * of {@link OAuth2AuthorizedClient Authorized Client(s)}.
 *
 * <p>
 * The primary responsibilities include:
 * <ol>
 *  <li>Authorizing (or re-authorizing) an OAuth 2.0 Client
 *  	by leveraging a {@link ReactiveOAuth2AuthorizedClientProvider}(s).</li>
 *  <li>Managing the persistence of an {@link OAuth2AuthorizedClient} between requests,
 *  	typically using an {@link ServerOAuth2AuthorizedClientRepository}.</li>
 * </ol>
 *
 * @author Joe Grandja
 * @since 5.2
 * @see OAuth2AuthorizedClient
 * @see ReactiveOAuth2AuthorizedClientProvider
 * @see ServerOAuth2AuthorizedClientRepository
 */
public interface ServerOAuth2AuthorizedClientManager {

	/**
	 * Attempt to authorize or re-authorize (if required) the {@link ClientRegistration client}
	 * identified by the provided {@link ServerOAuth2AuthorizeRequest#getClientRegistrationId() clientRegistrationId}.
	 * Implementations must return {@code null} if authorization is not supported for the specified client,
	 * e.g. the associated {@link ReactiveOAuth2AuthorizedClientProvider}(s) does not support
	 * the {@link ClientRegistration#getAuthorizationGrantType() authorization grant} type configured for the client.
	 *
	 * <p>
	 * In the case of re-authorization, implementations must return the provided {@link ServerOAuth2AuthorizeRequest#getAuthorizedClient() authorized client}
	 * if re-authorization is not supported for the client OR is not required,
	 * e.g. a {@link OAuth2AuthorizedClient#getRefreshToken() refresh token} is not available OR
	 * the {@link OAuth2AuthorizedClient#getAccessToken() access token} is not expired.
	 *
	 * @param authorizeRequest the authorize request
	 * @return the {@link OAuth2AuthorizedClient} or {@code null} if authorization is not supported for the specified client
	 */
	@Nullable
	Mono<OAuth2AuthorizedClient> authorize(ServerOAuth2AuthorizeRequest authorizeRequest);

}
