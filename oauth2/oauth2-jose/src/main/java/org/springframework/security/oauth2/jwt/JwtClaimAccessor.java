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
package org.springframework.security.oauth2.jwt;

import java.net.URL;
import java.time.Instant;
import java.util.List;

import org.springframework.security.oauth2.core.ClaimAccessor;

/**
 * A {@link ClaimAccessor} for the &quot;claims&quot; that may be contained in the JSON
 * object JWT Claims Set of a JSON Web Token (JWT).
 *
 * @author Joe Grandja
 * @since 5.0
 * @see ClaimAccessor
 * @see JwtClaimNames
 * @see Jwt
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc7519#section-4.1">Registered Claim Names</a>
 */
public interface JwtClaimAccessor extends ClaimAccessor {

	/**
	 * Returns the Issuer {@code (iss)} claim which identifies the principal that issued
	 * the JWT.
	 * @return the Issuer identifier
	 */
	default URL getIssuer() {
		return this.getClaimAsURL(JwtClaimNames.ISS);
	}

	/**
	 * Returns the Subject {@code (sub)} claim which identifies the principal that is the
	 * subject of the JWT.
	 * @return the Subject identifier
	 */
	default String getSubject() {
		return this.getClaimAsString(JwtClaimNames.SUB);
	}

	/**
	 * Returns the Audience {@code (aud)} claim which identifies the recipient(s) that the
	 * JWT is intended for.
	 * @return the Audience(s) that this JWT intended for
	 */
	default List<String> getAudience() {
		return this.getClaimAsStringList(JwtClaimNames.AUD);
	}

	/**
	 * Returns the Expiration time {@code (exp)} claim which identifies the expiration
	 * time on or after which the JWT MUST NOT be accepted for processing.
	 * @return the Expiration time on or after which the JWT MUST NOT be accepted for
	 * processing
	 */
	default Instant getExpiresAt() {
		return this.getClaimAsInstant(JwtClaimNames.EXP);
	}

	/**
	 * Returns the Not Before {@code (nbf)} claim which identifies the time before which
	 * the JWT MUST NOT be accepted for processing.
	 * @return the Not Before time before which the JWT MUST NOT be accepted for
	 * processing
	 */
	default Instant getNotBefore() {
		return this.getClaimAsInstant(JwtClaimNames.NBF);
	}

	/**
	 * Returns the Issued at {@code (iat)} claim which identifies the time at which the
	 * JWT was issued.
	 * @return the Issued at claim which identifies the time at which the JWT was issued
	 */
	default Instant getIssuedAt() {
		return this.getClaimAsInstant(JwtClaimNames.IAT);
	}

	/**
	 * Returns the JWT ID {@code (jti)} claim which provides a unique identifier for the
	 * JWT.
	 * @return the JWT ID claim which provides a unique identifier for the JWT
	 */
	default String getId() {
		return this.getClaimAsString(JwtClaimNames.JTI);
	}

}
