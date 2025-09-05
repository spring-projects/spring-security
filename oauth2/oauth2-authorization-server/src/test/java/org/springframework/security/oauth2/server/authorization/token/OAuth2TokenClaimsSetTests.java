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

package org.springframework.security.oauth2.server.authorization.token;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link OAuth2TokenClaimsSet}.
 *
 * @author Joe Grandja
 */
public class OAuth2TokenClaimsSetTests {

	@Test
	public void buildWhenClaimsEmptyThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> OAuth2TokenClaimsSet.builder().build())
			.withMessage("claims cannot be empty");
	}

	@Test
	public void buildWhenAllClaimsProvidedThenAllClaimsAreSet() {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);
		String customClaimName = "custom-claim-name";
		String customClaimValue = "custom-claim-value";

		// @formatter:off
		OAuth2TokenClaimsSet expectedClaimsSet = OAuth2TokenClaimsSet.builder()
				.issuer("https://provider.com")
				.subject("subject")
				.audience(Collections.singletonList("client-1"))
				.issuedAt(issuedAt)
				.notBefore(issuedAt)
				.expiresAt(expiresAt)
				.id("id")
				.claims((claims) -> claims.put(customClaimName, customClaimValue))
				.build();

		OAuth2TokenClaimsSet claimsSet = OAuth2TokenClaimsSet.builder()
				.issuer(expectedClaimsSet.getIssuer().toExternalForm())
				.subject(expectedClaimsSet.getSubject())
				.audience(expectedClaimsSet.getAudience())
				.issuedAt(expectedClaimsSet.getIssuedAt())
				.notBefore(expectedClaimsSet.getNotBefore())
				.expiresAt(expectedClaimsSet.getExpiresAt())
				.id(expectedClaimsSet.getId())
				.claims((claims) -> claims.put(customClaimName, expectedClaimsSet.getClaim(customClaimName)))
				.build();
		// @formatter:on

		assertThat(claimsSet.getIssuer()).isEqualTo(expectedClaimsSet.getIssuer());
		assertThat(claimsSet.getSubject()).isEqualTo(expectedClaimsSet.getSubject());
		assertThat(claimsSet.getAudience()).isEqualTo(expectedClaimsSet.getAudience());
		assertThat(claimsSet.getIssuedAt()).isEqualTo(expectedClaimsSet.getIssuedAt());
		assertThat(claimsSet.getNotBefore()).isEqualTo(expectedClaimsSet.getNotBefore());
		assertThat(claimsSet.getExpiresAt()).isEqualTo(expectedClaimsSet.getExpiresAt());
		assertThat(claimsSet.getId()).isEqualTo(expectedClaimsSet.getId());
		assertThat(claimsSet.<String>getClaim(customClaimName)).isEqualTo(expectedClaimsSet.getClaim(customClaimName));
		assertThat(claimsSet.getClaims()).isEqualTo(expectedClaimsSet.getClaims());
	}

	@Test
	public void claimWhenNameNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> OAuth2TokenClaimsSet.builder().claim(null, "value"))
			.withMessage("name cannot be empty");
	}

	@Test
	public void claimWhenValueNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> OAuth2TokenClaimsSet.builder().claim("name", null))
			.withMessage("value cannot be null");
	}

}
