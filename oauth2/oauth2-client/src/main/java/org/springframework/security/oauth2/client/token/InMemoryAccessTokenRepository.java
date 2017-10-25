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
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.util.Assert;

import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An <i>in-memory</i> {@link OAuth2TokenRepository} for {@link AccessToken}'s.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2TokenRepository
 * @see AccessToken
 * @see ClientRegistration
 * @see Authentication
 */
public final class InMemoryAccessTokenRepository implements OAuth2TokenRepository<AccessToken> {
	private final Map<String, AccessToken> accessTokens = new ConcurrentHashMap<>();

	@Override
	public AccessToken loadToken(ClientRegistration registration, Authentication principal) {
		Assert.notNull(registration, "registration cannot be null");
		Assert.notNull(principal, "principal cannot be null");
		return this.accessTokens.get(this.getIdentifier(registration, principal));
	}

	@Override
	public void saveToken(AccessToken accessToken, ClientRegistration registration, Authentication principal) {
		Assert.notNull(accessToken, "accessToken cannot be null");
		Assert.notNull(registration, "registration cannot be null");
		Assert.notNull(principal, "principal cannot be null");
		this.accessTokens.put(this.getIdentifier(registration, principal), accessToken);
	}

	@Override
	public AccessToken removeToken(ClientRegistration registration, Authentication principal) {
		Assert.notNull(registration, "registration cannot be null");
		Assert.notNull(principal, "principal cannot be null");
		return this.accessTokens.remove(this.getIdentifier(registration, principal));
	}

	private String getIdentifier(ClientRegistration registration, Authentication principal) {
		String identifier = "[" + registration.getRegistrationId() + "][" + principal.getName() + "]";
		return Base64.getEncoder().encodeToString(identifier.getBytes());
	}
}
