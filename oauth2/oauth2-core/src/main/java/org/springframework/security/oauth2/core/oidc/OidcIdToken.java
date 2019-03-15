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

import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

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
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#IDToken">ID Token</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">Standard Claims</a>
 */
public class OidcIdToken extends AbstractOAuth2Token implements IdTokenClaimAccessor {
	private final Map<String, Object> claims;

	/**
	 * Constructs a {@code OidcIdToken} using the provided parameters.
	 *
	 * @param tokenValue the ID Token value
	 * @param issuedAt the time at which the ID Token was issued {@code (iat)}
	 * @param expiresAt the expiration time {@code (exp)} on or after which the ID Token MUST NOT be accepted
	 * @param claims the claims about the authentication of the End-User
	 */
	public OidcIdToken(String tokenValue, Instant issuedAt, Instant expiresAt, Map<String, Object> claims) {
		super(tokenValue, issuedAt, expiresAt);
		Assert.notEmpty(claims, "claims cannot be empty");
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	@Override
	public Map<String, Object> getClaims() {
		return this.claims;
	}
}
