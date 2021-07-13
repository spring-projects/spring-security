/*
 * Copyright 2002-2021 the original author or authors.
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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;

/**
 * @author Joe Grandja
 */
public final class TestJwtClaimsSets {

	private TestJwtClaimsSets() {
	}

	public static JwtClaimsSet.Builder jwtClaimsSet() {
		String issuer = "https://provider.com";
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);

		// @formatter:off
		return JwtClaimsSet.builder()
				.issuer(issuer)
				.subject("subject")
				.audience(Collections.singletonList("client-1"))
				.issuedAt(issuedAt)
				.notBefore(issuedAt)
				.expiresAt(expiresAt)
				.id("jti")
				.claim("custom-claim-name", "custom-claim-value");
		// @formatter:on
	}

}
