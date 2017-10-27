/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.userinfo;

import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Implementations of this interface are responsible for obtaining the user attributes
 * of the <i>End-User</i> (Resource Owner) from the <i>UserInfo Endpoint</i>
 * using the {@link OAuth2AuthorizedClient#getAccessToken() Access Token}
 * granted to the {@link OAuth2AuthorizedClient Authorized Client}
 * and returning an {@link AuthenticatedPrincipal} in the form of an {@link OAuth2User}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2AuthorizedClient
 * @see OAuth2User
 * @see AuthenticatedPrincipal
 *
 * @param <C> The type of <i>Authorized Client</i>
 * @param <U> The type of <i>OAuth 2.0 User</i>
 */
public interface OAuth2UserService<C extends OAuth2AuthorizedClient, U extends OAuth2User> {

	U loadUser(C authorizedClient) throws OAuth2AuthenticationException;

}
