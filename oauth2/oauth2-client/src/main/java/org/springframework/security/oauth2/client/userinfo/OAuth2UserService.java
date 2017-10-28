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
package org.springframework.security.oauth2.client.userinfo;

import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Implementations of this interface are responsible for obtaining the user attributes
 * of the <i>End-User</i> (Resource Owner) from the <i>UserInfo Endpoint</i>
 * using the {@link OAuth2UserRequest#getAccessToken() Access Token}
 * granted to the {@link OAuth2UserRequest#getClientRegistration() Client}
 * and returning an {@link AuthenticatedPrincipal} in the form of an {@link OAuth2User}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2UserRequest
 * @see OAuth2User
 * @see AuthenticatedPrincipal
 *
 * @param <R> The type of <i>OAuth 2.0 User Request</i>
 * @param <U> The type of <i>OAuth 2.0 User</i>
 */
public interface OAuth2UserService<R extends OAuth2UserRequest, U extends OAuth2User> {

	U loadUser(R userRequest) throws OAuth2AuthenticationException;

}
