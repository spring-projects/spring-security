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

package org.springframework.security.oauth2.core.oidc;

import java.net.URL;
import java.time.Instant;
import java.util.List;

import org.jspecify.annotations.Nullable;

import org.springframework.security.oauth2.core.ClaimAccessor;

/**
 * A {@link ClaimAccessor} for the &quot;claims&quot; that can be returned in the ID
 * Token, which provides information about the authentication of an End-User by an
 * Authorization Server.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see ClaimAccessor
 * @see StandardClaimAccessor
 * @see StandardClaimNames
 * @see IdTokenClaimNames
 * @see OidcIdToken
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-core-1_0.html#IDToken">ID Token</a>
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">Standard
 * Claims</a>
 */
public interface IdTokenClaimAccessor extends StandardClaimAccessor {

	/**
	 * Returns the Issuer identifier {@code (iss)}, or {@code null} if it does not exist.
	 * @return the Issuer identifier, or {@code null} if it does not exist
	 */
	default @Nullable URL getIssuer() {
		return this.getClaimAsURL(IdTokenClaimNames.ISS);
	}

	/**
	 * Returns the Subject identifier {@code (sub)}, or {@code null} if it does not exist.
	 * @return the Subject identifier, or {@code null} if it does not exist
	 */
	@Override
	default @Nullable String getSubject() {
		return this.getClaimAsString(IdTokenClaimNames.SUB);
	}

	/**
	 * Returns the Audience(s) {@code (aud)} that this ID Token is intended for, or
	 * {@code null} if it does not exist.
	 * @return the Audience(s) that this ID Token is intended for, or {@code null} if it
	 * does not exist
	 */
	default @Nullable List<String> getAudience() {
		return this.getClaimAsStringList(IdTokenClaimNames.AUD);
	}

	/**
	 * Returns the Expiration time {@code (exp)} on or after which the ID Token MUST NOT
	 * be accepted, or {@code null} if it does not exist.
	 * @return the Expiration time on or after which the ID Token MUST NOT be accepted, or
	 * {@code null} if it does not exist
	 */
	default @Nullable Instant getExpiresAt() {
		return this.getClaimAsInstant(IdTokenClaimNames.EXP);
	}

	/**
	 * Returns the time at which the ID Token was issued {@code (iat)}, or {@code null} if
	 * it does not exist.
	 * @return the time at which the ID Token was issued, or {@code null} if it does not
	 * exist
	 */
	default @Nullable Instant getIssuedAt() {
		return this.getClaimAsInstant(IdTokenClaimNames.IAT);
	}

	/**
	 * Returns the time when the End-User authentication occurred {@code (auth_time)}, or
	 * {@code null} if it does not exist.
	 * @return the time when the End-User authentication occurred, or {@code null} if it
	 * does not exist
	 */
	default @Nullable Instant getAuthenticatedAt() {
		return this.getClaimAsInstant(IdTokenClaimNames.AUTH_TIME);
	}

	/**
	 * Returns a {@code String} value {@code (nonce)} used to associate a Client session
	 * with an ID Token, and to mitigate replay attacks, or {@code null} if it does not
	 * exist.
	 * @return the nonce used to associate a Client session with an ID Token, or
	 * {@code null} if it does not exist
	 */
	default @Nullable String getNonce() {
		return this.getClaimAsString(IdTokenClaimNames.NONCE);
	}

	/**
	 * Returns the Authentication Context Class Reference {@code (acr)}, or {@code null}
	 * if it does not exist.
	 * @return the Authentication Context Class Reference, or {@code null} if it does not
	 * exist
	 */
	default @Nullable String getAuthenticationContextClass() {
		return this.getClaimAsString(IdTokenClaimNames.ACR);
	}

	/**
	 * Returns the Authentication Methods References {@code (amr)}, or {@code null} if it
	 * does not exist.
	 * @return the Authentication Methods References, or {@code null} if it does not exist
	 */
	default @Nullable List<String> getAuthenticationMethods() {
		return this.getClaimAsStringList(IdTokenClaimNames.AMR);
	}

	/**
	 * Returns the Authorized party {@code (azp)} to which the ID Token was issued, or
	 * {@code null} if it does not exist.
	 * @return the Authorized party to which the ID Token was issued, or {@code null} if
	 * it does not exist
	 */
	default @Nullable String getAuthorizedParty() {
		return this.getClaimAsString(IdTokenClaimNames.AZP);
	}

	/**
	 * Returns the Access Token hash value {@code (at_hash)}, or {@code null} if it does
	 * not exist.
	 * @return the Access Token hash value, or {@code null} if it does not exist
	 */
	default @Nullable String getAccessTokenHash() {
		return this.getClaimAsString(IdTokenClaimNames.AT_HASH);
	}

	/**
	 * Returns the Authorization Code hash value {@code (c_hash)}, or {@code null} if it
	 * does not exist.
	 * @return the Authorization Code hash value, or {@code null} if it does not exist
	 */
	default @Nullable String getAuthorizationCodeHash() {
		return this.getClaimAsString(IdTokenClaimNames.C_HASH);
	}

}
