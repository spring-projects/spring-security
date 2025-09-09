/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.authorization;

import java.security.Principal;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * Implementations of this interface are responsible for the management of
 * {@link OAuth2AuthorizationConsent OAuth 2.0 Authorization Consent(s)}.
 *
 * @author Daniel Garnier-Moiroux
 * @since 7.0
 * @see OAuth2AuthorizationConsent
 */
public interface OAuth2AuthorizationConsentService {

	/**
	 * Saves the {@link OAuth2AuthorizationConsent}.
	 * @param authorizationConsent the {@link OAuth2AuthorizationConsent}
	 */
	void save(OAuth2AuthorizationConsent authorizationConsent);

	/**
	 * Removes the {@link OAuth2AuthorizationConsent}.
	 * @param authorizationConsent the {@link OAuth2AuthorizationConsent}
	 */
	void remove(OAuth2AuthorizationConsent authorizationConsent);

	/**
	 * Returns the {@link OAuth2AuthorizationConsent} identified by the provided
	 * {@code registeredClientId} and {@code principalName}, or {@code null} if not found.
	 * @param registeredClientId the identifier for the {@link RegisteredClient}
	 * @param principalName the name of the {@link Principal}
	 * @return the {@link OAuth2AuthorizationConsent} if found, otherwise {@code null}
	 */
	@Nullable
	OAuth2AuthorizationConsent findById(String registeredClientId, String principalName);

}
