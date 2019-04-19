/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.core.oidc;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.core.AbstractOAuth2Token;

/**
 * An implementation of an {@link AbstractOAuth2Token} representing an OpenID Connect Core 1.0 ID Token.
 *
 * <p>
 * The {@code OidcIdToken} is a security token that contains &quot;claims&quot;
 * about the authentication of an End-User by an Authorization Server.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AbstractOAuth2Token
 * @see IdTokenClaimAccessor
 * @see StandardClaimAccessor
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">ID Token</a>
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">Standard Claims</a>
 */
public class OidcIdToken extends AbstractOAuth2Token implements IdTokenClaimAccessor {

	/**
	 * Constructs a {@code OidcIdToken} using the provided parameters.
	 *
	 * @param tokenValue the ID Token value
	 * @param claims the claims about the authentication of the End-User
	 */
	public OidcIdToken(final String tokenValue, final Map<String, Object> claims) {
		super(tokenValue, claims);
	}
	
	/**
	 * Constructs a {@code OidcIdToken} using the provided parameters.
	 *
	 * @param tokenValue the ID Token value
	 * @param issuedAt the time at which the ID Token was issued {@code (iat)}
	 * @param expiresAt the expiration time {@code (exp)} on or after which the ID Token MUST NOT be accepted
	 * @param claims the claims about the authentication of the End-User
	 * @deprecated provide issue and expiration instants as claims. If non null "issuedAt" is provided and "iat" claim is there too, then first wins (claim is overridden). Same for expiration.
	 */
	@Deprecated
	public OidcIdToken(String tokenValue, Instant issuedAt, Instant expiresAt, Map<String, Object> claims) {
		this(tokenValue, withInstants(claims, issuedAt, expiresAt));
	}

	private static Map<String, Object> withInstants(final Map<String, Object> claims, final Instant issuedAt, final Instant expiresAt) {
		final Map<String, Object> attributes = new HashMap<>(claims);
		if(issuedAt != null) attributes.put(IdTokenClaimNames.IAT, issuedAt);
		if(expiresAt != null) attributes.put(IdTokenClaimNames.EXP, expiresAt);
		return attributes;
	}

	@Override
	public Map<String, Object> getClaims() {
		return getAttributes();
	}

	@Override
	public Instant getIssuedAt() {
		return getClaimAsInstant(IdTokenClaimNames.IAT);
	}

	@Override
	public Instant getExpiresAt() {
		return getClaimAsInstant(IdTokenClaimNames.EXP);
	}
}
