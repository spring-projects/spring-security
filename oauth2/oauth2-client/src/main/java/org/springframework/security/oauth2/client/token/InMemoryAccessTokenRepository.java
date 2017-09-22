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
import org.springframework.security.oauth2.client.registration.ClientRegistrationIdentifierStrategy;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.util.Assert;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * A {@link SecurityTokenRepository} that associates an {@link AccessToken}
 * to a {@link ClientRegistration Client} and stores it <i>in-memory</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see SecurityTokenRepository
 * @see AccessToken
 * @see ClientRegistration
 */
public final class InMemoryAccessTokenRepository implements SecurityTokenRepository<AccessToken> {
	private final ClientRegistrationIdentifierStrategy<String> identifierStrategy = new AuthorizedClientIdentifierStrategy();
	private final Map<String, AccessToken> accessTokens = new HashMap<>();

	@Override
	public AccessToken loadSecurityToken(ClientRegistration registration) {
		Assert.notNull(registration, "registration cannot be null");
		return this.accessTokens.get(this.identifierStrategy.getIdentifier(registration));
	}

	@Override
	public void saveSecurityToken(AccessToken accessToken, ClientRegistration registration) {
		Assert.notNull(accessToken, "accessToken cannot be null");
		Assert.notNull(registration, "registration cannot be null");
		this.accessTokens.put(this.identifierStrategy.getIdentifier(registration), accessToken);
	}

	@Override
	public void removeSecurityToken(ClientRegistration registration) {
		Assert.notNull(registration, "registration cannot be null");
		this.accessTokens.remove(this.identifierStrategy.getIdentifier(registration));
	}

	/**
	 * A client is considered <i>&quot;authorized&quot;</i>, if it receives a successful response from the <i>Token Endpoint</i>.
	 *
	 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request</a>
	 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-5.1">Section 5.1 Access Token Response</a>
	 */
	private static class AuthorizedClientIdentifierStrategy implements ClientRegistrationIdentifierStrategy<String> {

		@Override
		public String getIdentifier(ClientRegistration clientRegistration) {
			StringBuilder builder = new StringBuilder();

			// Access Token Request attributes
			builder.append("[").append(clientRegistration.getAuthorizationGrantType().getValue()).append("]");
			builder.append("[").append(clientRegistration.getRedirectUri()).append("]");
			builder.append("[").append(clientRegistration.getClientId()).append("]");

			// Access Token Response attributes
			builder.append("[").append(clientRegistration.getScope().toString()).append("]");

			// Client alias is unique as well
			builder.append("[").append(clientRegistration.getClientAlias()).append("]");

			return Base64.getEncoder().encodeToString(builder.toString().getBytes());
		}
	}
}

