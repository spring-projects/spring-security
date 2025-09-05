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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthorizationConsentService} that stores
 * {@link OAuth2AuthorizationConsent}'s in-memory.
 *
 * <p>
 * <b>NOTE:</b> This implementation should ONLY be used during development/testing.
 *
 * @author Daniel Garnier-Moiroux
 * @since 0.1.2
 * @see OAuth2AuthorizationConsentService
 */
public final class InMemoryOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService {

	private final Map<Integer, OAuth2AuthorizationConsent> authorizationConsents = new ConcurrentHashMap<>();

	/**
	 * Constructs an {@code InMemoryOAuth2AuthorizationConsentService}.
	 */
	public InMemoryOAuth2AuthorizationConsentService() {
		this(Collections.emptyList());
	}

	/**
	 * Constructs an {@code InMemoryOAuth2AuthorizationConsentService} using the provided
	 * parameters.
	 * @param authorizationConsents the authorization consent(s)
	 */
	public InMemoryOAuth2AuthorizationConsentService(OAuth2AuthorizationConsent... authorizationConsents) {
		this(Arrays.asList(authorizationConsents));
	}

	/**
	 * Constructs an {@code InMemoryOAuth2AuthorizationConsentService} using the provided
	 * parameters.
	 * @param authorizationConsents the authorization consent(s)
	 */
	public InMemoryOAuth2AuthorizationConsentService(List<OAuth2AuthorizationConsent> authorizationConsents) {
		Assert.notNull(authorizationConsents, "authorizationConsents cannot be null");
		authorizationConsents.forEach((authorizationConsent) -> {
			Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
			int id = getId(authorizationConsent);
			Assert.isTrue(!this.authorizationConsents.containsKey(id),
					"The authorizationConsent must be unique. Found duplicate, with registered client id: ["
							+ authorizationConsent.getRegisteredClientId() + "] and principal name: ["
							+ authorizationConsent.getPrincipalName() + "]");
			this.authorizationConsents.put(id, authorizationConsent);
		});
	}

	@Override
	public void save(OAuth2AuthorizationConsent authorizationConsent) {
		Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
		int id = getId(authorizationConsent);
		this.authorizationConsents.put(id, authorizationConsent);
	}

	@Override
	public void remove(OAuth2AuthorizationConsent authorizationConsent) {
		Assert.notNull(authorizationConsent, "authorizationConsent cannot be null");
		int id = getId(authorizationConsent);
		this.authorizationConsents.remove(id, authorizationConsent);
	}

	@Override
	@Nullable
	public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
		Assert.hasText(registeredClientId, "registeredClientId cannot be empty");
		Assert.hasText(principalName, "principalName cannot be empty");
		int id = getId(registeredClientId, principalName);
		return this.authorizationConsents.get(id);
	}

	private static int getId(String registeredClientId, String principalName) {
		return Objects.hash(registeredClientId, principalName);
	}

	private static int getId(OAuth2AuthorizationConsent authorizationConsent) {
		return getId(authorizationConsent.getRegisteredClientId(), authorizationConsent.getPrincipalName());
	}

}
