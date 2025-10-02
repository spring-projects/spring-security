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

package org.springframework.security.core.authority;

import java.time.Instant;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests {@link FactorGrantedAuthority}.
 *
 * @author Yoobin Yoon
 * @author Rob Winch
 */
public class FactorGrantedAuthorityTests {

	@Test
	public void buildWhenOnlyAuthorityThenDefaultsIssuedAtToNow() {
		Instant before = Instant.now();

		FactorGrantedAuthority authority = FactorGrantedAuthority.withAuthority("profile:read").build();

		Instant after = Instant.now();

		assertThat(authority.getAuthority()).isEqualTo("profile:read");
		assertThat(authority.getIssuedAt()).isBetween(before, after);
	}

	@Test
	public void buildWhenAllFieldsSetThenCreatesCorrectly() {
		Instant issuedAt = Instant.now();

		FactorGrantedAuthority authority = FactorGrantedAuthority.withAuthority("admin:write")
			.issuedAt(issuedAt)
			.build();

		assertThat(authority.getAuthority()).isEqualTo("admin:write");
		assertThat(authority.getIssuedAt()).isEqualTo(issuedAt);
	}

	@Test
	public void buildWhenNullAuthorityThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> FactorGrantedAuthority.withAuthority(null))
			.withMessage("A granted authority textual representation is required");
	}

	@Test
	public void buildWhenEmptyAuthorityThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> FactorGrantedAuthority.withAuthority(""))
			.withMessage("A granted authority textual representation is required");
	}

}
