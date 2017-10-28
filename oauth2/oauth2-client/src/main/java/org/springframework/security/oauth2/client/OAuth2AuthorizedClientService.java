/*
 * Copyright 2002-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.OidcAuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * Implementations of this interface are responsible for the management
 * of {@link OAuth2AuthorizedClient Authorized Client(s)}, which provide the purpose
 * of associating an {@link OAuth2AuthorizedClient#getAccessToken() Access Token} to a
 * {@link OAuth2AuthorizedClient#getClientRegistration() Client} and <i>Resource Owner</i>,
 * who is the {@link OAuth2AuthorizedClient#getPrincipalName() Principal}
 * that originally granted the authorization.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2AuthorizedClient
 * @see OidcAuthorizedClient
 * @see ClientRegistration
 * @see Authentication
 *
 * @param <T> The type of <i>OAuth 2.0 Authorized Client</i>
 */
public interface OAuth2AuthorizedClientService<T extends OAuth2AuthorizedClient> {

	T loadAuthorizedClient(String clientRegistrationId, Authentication principal);

	void saveAuthorizedClient(T authorizedClient, Authentication principal);

	T removeAuthorizedClient(String clientRegistrationId, Authentication principal);

}
