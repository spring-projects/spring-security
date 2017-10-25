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
package org.springframework.security.oauth2.client.token;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;

/**
 * Implementations of this interface are responsible for the persistence
 * and association of an {@link AbstractOAuth2Token OAuth 2.0 Token}
 * to a {@link ClientRegistration Client} and <i>Resource Owner</i>,
 * which is the {@link Authentication Principal} who originally granted the authorization.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AbstractOAuth2Token
 * @see ClientRegistration
 * @see Authentication
 */
public interface OAuth2TokenRepository<T extends AbstractOAuth2Token> {

	T loadToken(ClientRegistration registration, Authentication principal);

	void saveToken(T token, ClientRegistration registration, Authentication principal);

	T removeToken(ClientRegistration registration, Authentication principal);

}
