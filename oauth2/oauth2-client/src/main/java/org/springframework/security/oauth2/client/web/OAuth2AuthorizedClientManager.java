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
package org.springframework.security.oauth2.client.web;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Implementations of this interface are responsible for the overall management
 * of {@link OAuth2AuthorizedClient Authorized Client(s)}.
 *
 * <p>
 * The primary responsibilities include:
 * <ol>
 *  <li>Authorizing (or re-authorizing) an OAuth 2.0 Client
 *  	by leveraging an {@link OAuth2AuthorizedClientProvider}(s).</li>
 *  <li>Managing the persistence of an {@link OAuth2AuthorizedClient} between requests,
 *  	typically using an {@link OAuth2AuthorizedClientRepository}.</li>
 * </ol>
 *
 * @author Joe Grandja
 * @since 5.2
 * @see OAuth2AuthorizedClient
 * @see OAuth2AuthorizedClientProvider
 * @see OAuth2AuthorizedClientRepository
 */
public interface OAuth2AuthorizedClientManager {

	/**
	 * Attempt to authorize or re-authorize (if required) the {@link ClientRegistration client}
	 * identified by the provided {@code clientRegistrationId}.
	 * Implementations must return {@code null} if authorization is not supported for the specified client,
	 * e.g. the associated {@link OAuth2AuthorizedClientProvider}(s) does not support
	 * the {@link ClientRegistration#getAuthorizationGrantType() authorization grant} type configured for the client.
	 *
	 * @param clientRegistrationId the identifier for the client's registration
	 * @param principal the {@code Principal} {@link Authentication} (to be) associated to the authorized client
	 * @param request the {@code HttpServletRequest}
	 * @param response the {@code HttpServletResponse}
	 * @return the {@link OAuth2AuthorizedClient} or {@code null} if authorization is not supported for the specified client
	 */
	@Nullable
	OAuth2AuthorizedClient authorize(String clientRegistrationId, Authentication principal,
										HttpServletRequest request, HttpServletResponse response);

	/**
	 * Attempt to re-authorize (if required) the provided {@link OAuth2AuthorizedClient authorized client}.
	 * Implementations must return the provided {@code authorizedClient} if re-authorization is not supported
	 * for the {@link OAuth2AuthorizedClient#getClientRegistration() client} OR is not required,
	 * e.g. a {@link OAuth2AuthorizedClient#getRefreshToken() refresh token} is not available OR
	 * the {@link OAuth2AuthorizedClient#getAccessToken() access token} is not expired.
	 *
	 * @param authorizedClient the authorized client
	 * @param principal the {@code Principal} {@link Authentication} associated to the authorized client
	 * @param request the {@code HttpServletRequest}
	 * @param response the {@code HttpServletResponse}
	 * @return the re-authorized {@link OAuth2AuthorizedClient} or the provided {@code authorizedClient} if not re-authorized
	 */
	OAuth2AuthorizedClient reauthorize(OAuth2AuthorizedClient authorizedClient, Authentication principal,
										HttpServletRequest request, HttpServletResponse response);

}
