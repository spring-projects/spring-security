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

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;

/**
 * Implementations of this interface are responsible for the persistence
 * and association of an {@link AbstractOAuth2Token} to a {@link ClientRegistration Client}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AbstractOAuth2Token
 * @see ClientRegistration
 */
public interface SecurityTokenRepository<T extends AbstractOAuth2Token> {

	T loadSecurityToken(ClientRegistration registration);

	void saveSecurityToken(T securityToken, ClientRegistration registration);

	void removeSecurityToken(ClientRegistration registration);

}
