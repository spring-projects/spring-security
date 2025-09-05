/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.token;

import java.net.URL;
import java.time.Instant;
import java.util.List;

import org.springframework.security.oauth2.core.ClaimAccessor;

/**
 * A {@link ClaimAccessor} for the "claims" that may be contained in an
 * {@link OAuth2TokenClaimsSet}.
 *
 * @author Joe Grandja
 * @since 0.2.3
 * @see ClaimAccessor
 * @see OAuth2TokenClaimNames
 * @see OAuth2TokenClaimsSet
 */
public interface OAuth2TokenClaimAccessor extends ClaimAccessor {

	/**
	 * Returns the Issuer {@code (iss)} claim which identifies the principal that issued
	 * the OAuth 2.0 Token.
	 * @return the Issuer identifier
	 */
	default URL getIssuer() {
		return getClaimAsURL(OAuth2TokenClaimNames.ISS);
	}

	/**
	 * Returns the Subject {@code (sub)} claim which identifies the principal that is the
	 * subject of the OAuth 2.0 Token.
	 * @return the Subject identifier
	 */
	default String getSubject() {
		return getClaimAsString(OAuth2TokenClaimNames.SUB);
	}

	/**
	 * Returns the Audience {@code (aud)} claim which identifies the recipient(s) that the
	 * OAuth 2.0 Token is intended for.
	 * @return the Audience(s) that this OAuth 2.0 Token is intended for
	 */
	default List<String> getAudience() {
		return getClaimAsStringList(OAuth2TokenClaimNames.AUD);
	}

	/**
	 * Returns the Expiration time {@code (exp)} claim which identifies the expiration
	 * time on or after which the OAuth 2.0 Token MUST NOT be accepted for processing.
	 * @return the Expiration time on or after which the OAuth 2.0 Token MUST NOT be
	 * accepted for processing
	 */
	default Instant getExpiresAt() {
		return getClaimAsInstant(OAuth2TokenClaimNames.EXP);
	}

	/**
	 * Returns the Not Before {@code (nbf)} claim which identifies the time before which
	 * the OAuth 2.0 Token MUST NOT be accepted for processing.
	 * @return the Not Before time before which the OAuth 2.0 Token MUST NOT be accepted
	 * for processing
	 */
	default Instant getNotBefore() {
		return getClaimAsInstant(OAuth2TokenClaimNames.NBF);
	}

	/**
	 * Returns the Issued at {@code (iat)} claim which identifies the time at which the
	 * OAuth 2.0 Token was issued.
	 * @return the Issued at claim which identifies the time at which the OAuth 2.0 Token
	 * was issued
	 */
	default Instant getIssuedAt() {
		return getClaimAsInstant(OAuth2TokenClaimNames.IAT);
	}

	/**
	 * Returns the ID {@code (jti)} claim which provides a unique identifier for the OAuth
	 * 2.0 Token.
	 * @return the ID claim which provides a unique identifier for the OAuth 2.0 Token
	 */
	default String getId() {
		return getClaimAsString(OAuth2TokenClaimNames.JTI);
	}

}
