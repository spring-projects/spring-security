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
package org.springframework.security.jwt;

import org.springframework.security.oauth2.core.ClaimAccessor;

import java.net.URL;
import java.time.Instant;
import java.util.List;

/**
 * A {@link ClaimAccessor} for the &quot;Registered Claim Names&quot;
 * that may be contained in the JSON object <i>JWT Claims Set</i> of a <i>JSON Web Token (JWT)</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see ClaimAccessor
 * @see JwtClaim
 * @see Jwt
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519#section-4.1">Registered Claim Names</a>
 */
public interface JwtClaimAccessor extends ClaimAccessor {

	default URL getIssuer() {
		return this.getClaimAsURL(JwtClaim.ISS);
	}

	default String getSubject() {
		return this.getClaimAsString(JwtClaim.SUB);
	}

	default List<String> getAudience() {
		return this.getClaimAsStringList(JwtClaim.AUD);
	}

	default Instant getExpiresAt() {
		return this.getClaimAsInstant(JwtClaim.EXP);
	}

	default Instant getNotBefore() {
		return this.getClaimAsInstant(JwtClaim.NBF);
	}

	default Instant getIssuedAt() {
		return this.getClaimAsInstant(JwtClaim.IAT);
	}

	default String getId() {
		return this.getClaimAsString(JwtClaim.JTI);
	}
}
