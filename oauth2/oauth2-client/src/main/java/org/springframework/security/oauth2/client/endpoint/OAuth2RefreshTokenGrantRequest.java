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
package org.springframework.security.oauth2.client.endpoint;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * An OAuth 2.0 Refresh Token Grant request that holds
 * the {@link OAuth2AuthorizedClient authorized client}.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see AbstractOAuth2AuthorizationGrantRequest
 * @see OAuth2AuthorizedClient
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-6">Section 6 Refreshing an Access Token</a>
 */
public class OAuth2RefreshTokenGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {
	private final OAuth2AuthorizedClient authorizedClient;
	private final Set<String> scopes;

	/**
	 * Constructs an {@code OAuth2RefreshTokenGrantRequest} using the provided parameters.
	 *
	 * @param authorizedClient the authorized client
	 */
	public OAuth2RefreshTokenGrantRequest(OAuth2AuthorizedClient authorizedClient) {
		this(authorizedClient, Collections.emptySet());
	}

	/**
	 * Constructs an {@code OAuth2RefreshTokenGrantRequest} using the provided parameters.
	 *
	 * @param authorizedClient the authorized client
	 * @param scopes the scopes
	 */
	public OAuth2RefreshTokenGrantRequest(OAuth2AuthorizedClient authorizedClient, Set<String> scopes) {
		super(AuthorizationGrantType.REFRESH_TOKEN);
		Assert.notNull(authorizedClient, "authorizedClient cannot be null");
		Assert.notNull(authorizedClient.getRefreshToken(), "authorizedClient.refreshToken cannot be null");
		this.authorizedClient = authorizedClient;
		this.scopes = Collections.unmodifiableSet(scopes != null ?
				new LinkedHashSet<>(scopes) : Collections.emptySet());

	}

	/**
	 * Returns the {@link OAuth2AuthorizedClient authorized client}.
	 *
	 * @return the {@link OAuth2AuthorizedClient}
	 */
	public OAuth2AuthorizedClient getAuthorizedClient() {
		return this.authorizedClient;
	}

	/**
	 * Returns the scope(s).
	 *
	 * @return the scope(s)
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}
}
