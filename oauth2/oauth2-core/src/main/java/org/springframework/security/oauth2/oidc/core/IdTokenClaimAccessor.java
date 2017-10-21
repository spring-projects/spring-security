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
package org.springframework.security.oauth2.oidc.core;

import org.springframework.security.oauth2.core.ClaimAccessor;

import java.net.URL;
import java.time.Instant;
import java.util.List;

/**
 * A {@link ClaimAccessor} for the &quot;Claims&quot; that can be returned in the <i>ID Token</i>
 * which provides information about the authentication of an End-User by an Authorization Server.
 *
 * @see ClaimAccessor
 * @see StandardClaimAccessor
 * @see StandardClaim
 * @see IdTokenClaim
 * @see IdToken
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#IDToken">ID Token</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">Standard Claims</a>
 * @author Joe Grandja
 * @since 5.0
 */
public interface IdTokenClaimAccessor extends StandardClaimAccessor {

	default URL getIssuer() {
		return this.getClaimAsURL(IdTokenClaim.ISS);
	}

	default String getSubject() {
		return this.getClaimAsString(IdTokenClaim.SUB);
	}

	default List<String> getAudience() {
		return this.getClaimAsStringList(IdTokenClaim.AUD);
	}

	default Instant getExpiresAt() {
		return this.getClaimAsInstant(IdTokenClaim.EXP);
	}

	default Instant getIssuedAt() {
		return this.getClaimAsInstant(IdTokenClaim.IAT);
	}

	default Instant getAuthenticatedAt() {
		return this.getClaimAsInstant(IdTokenClaim.AUTH_TIME);
	}

	default String getNonce() {
		return this.getClaimAsString(IdTokenClaim.NONCE);
	}

	default String getAuthenticationContextClass() {
		return this.getClaimAsString(IdTokenClaim.ACR);
	}

	default List<String> getAuthenticationMethods() {
		return this.getClaimAsStringList(IdTokenClaim.AMR);
	}

	default String getAuthorizedParty() {
		return this.getClaimAsString(IdTokenClaim.AZP);
	}

	default String getAccessTokenHash() {
		return this.getClaimAsString(IdTokenClaim.AT_HASH);
	}

	default String getAuthorizationCodeHash() {
		return this.getClaimAsString(IdTokenClaim.C_HASH);
	}
}
