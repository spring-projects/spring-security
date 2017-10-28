/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.core.oidc;

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
 * @see StandardClaimNames
 * @see IdTokenClaimNames
 * @see OidcIdToken
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#IDToken">ID Token</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">Standard Claims</a>
 * @author Joe Grandja
 * @since 5.0
 */
public interface IdTokenClaimAccessor extends StandardClaimAccessor {

	default URL getIssuer() {
		return this.getClaimAsURL(IdTokenClaimNames.ISS);
	}

	default String getSubject() {
		return this.getClaimAsString(IdTokenClaimNames.SUB);
	}

	default List<String> getAudience() {
		return this.getClaimAsStringList(IdTokenClaimNames.AUD);
	}

	default Instant getExpiresAt() {
		return this.getClaimAsInstant(IdTokenClaimNames.EXP);
	}

	default Instant getIssuedAt() {
		return this.getClaimAsInstant(IdTokenClaimNames.IAT);
	}

	default Instant getAuthenticatedAt() {
		return this.getClaimAsInstant(IdTokenClaimNames.AUTH_TIME);
	}

	default String getNonce() {
		return this.getClaimAsString(IdTokenClaimNames.NONCE);
	}

	default String getAuthenticationContextClass() {
		return this.getClaimAsString(IdTokenClaimNames.ACR);
	}

	default List<String> getAuthenticationMethods() {
		return this.getClaimAsStringList(IdTokenClaimNames.AMR);
	}

	default String getAuthorizedParty() {
		return this.getClaimAsString(IdTokenClaimNames.AZP);
	}

	default String getAccessTokenHash() {
		return this.getClaimAsString(IdTokenClaimNames.AT_HASH);
	}

	default String getAuthorizationCodeHash() {
		return this.getClaimAsString(IdTokenClaimNames.C_HASH);
	}
}
