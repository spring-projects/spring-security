/*
 * Copyright 2020-2024 the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimNames;
import org.springframework.util.Assert;

/**
 * A {@link ClaimAccessor} used for the OAuth 2.0 Token Exchange Grant to represent an
 * actor in a {@link OAuth2TokenExchangeCompositeAuthenticationToken} (e.g. the
 * "delegation" use case).
 *
 * @author Steve Riesenberg
 * @since 1.3
 * @see OAuth2TokenExchangeCompositeAuthenticationToken
 */
public final class OAuth2TokenExchangeActor implements ClaimAccessor {

	private final Map<String, Object> claims;

	public OAuth2TokenExchangeActor(Map<String, Object> claims) {
		Assert.notNull(claims, "claims cannot be null");
		this.claims = Collections.unmodifiableMap(claims);
	}

	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}

	public String getIssuer() {
		return getClaimAsString(OAuth2TokenClaimNames.ISS);
	}

	public String getSubject() {
		return getClaimAsString(OAuth2TokenClaimNames.SUB);
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof OAuth2TokenExchangeActor other)) {
			return false;
		}
		return Objects.equals(this.claims, other.claims);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.claims);
	}

}
