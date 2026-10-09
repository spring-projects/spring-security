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
 * Tests {@link TimestampedGrantedAuthority}.
 *
 * @author Yoobin Yoon
 */
public class TimestampedGrantedAuthorityTests {

	@Test
	public void buildWhenOnlyAuthorityThenDefaultsIssuedAtToNow() {
		Instant before = Instant.now();

		TimestampedGrantedAuthority authority = TimestampedGrantedAuthority.withAuthority("profile:read").build();

		Instant after = Instant.now();

		assertThat(authority.getAuthority()).isEqualTo("profile:read");
		assertThat(authority.getIssuedAt()).isBetween(before, after);
		assertThat(authority.getNotBefore()).isNull();
		assertThat(authority.getExpiresAt()).isNull();
	}

	@Test
	public void buildWhenAllFieldsSetThenCreatesCorrectly() {
		Instant issuedAt = Instant.now();
		Instant notBefore = issuedAt.plusSeconds(60);
		Instant expiresAt = issuedAt.plusSeconds(300);

		TimestampedGrantedAuthority authority = TimestampedGrantedAuthority.withAuthority("admin:write")
			.issuedAt(issuedAt)
			.notBefore(notBefore)
			.expiresAt(expiresAt)
			.build();

		assertThat(authority.getAuthority()).isEqualTo("admin:write");
		assertThat(authority.getIssuedAt()).isEqualTo(issuedAt);
		assertThat(authority.getNotBefore()).isEqualTo(notBefore);
		assertThat(authority.getExpiresAt()).isEqualTo(expiresAt);
	}

	@Test
	public void buildWhenNullAuthorityThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> TimestampedGrantedAuthority.withAuthority(null))
			.withMessage("A granted authority textual representation is required");
	}

	@Test
	public void buildWhenEmptyAuthorityThenThrowsException() {
		assertThatIllegalArgumentException().isThrownBy(() -> TimestampedGrantedAuthority.withAuthority(""))
			.withMessage("A granted authority textual representation is required");
	}

	@Test
	public void buildWhenNotBeforeBeforeIssuedAtThenThrowsException() {
		Instant issuedAt = Instant.now();
		Instant notBefore = issuedAt.minusSeconds(60);

		assertThatIllegalArgumentException().isThrownBy(
				() -> TimestampedGrantedAuthority.withAuthority("test").issuedAt(issuedAt).notBefore(notBefore).build())
			.withMessage("notBefore must not be before issuedAt");
	}

	@Test
	public void buildWhenExpiresAtBeforeIssuedAtThenThrowsException() {
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.minusSeconds(60);

		assertThatIllegalArgumentException().isThrownBy(
				() -> TimestampedGrantedAuthority.withAuthority("test").issuedAt(issuedAt).expiresAt(expiresAt).build())
			.withMessage("expiresAt must not be before issuedAt");
	}

	@Test
	public void buildWhenExpiresAtBeforeNotBeforeThenThrowsException() {
		Instant issuedAt = Instant.now();
		Instant notBefore = issuedAt.plusSeconds(60);
		Instant expiresAt = issuedAt.plusSeconds(30);

		assertThatIllegalArgumentException()
			.isThrownBy(() -> TimestampedGrantedAuthority.withAuthority("test")
				.issuedAt(issuedAt)
				.notBefore(notBefore)
				.expiresAt(expiresAt)
				.build())
			.withMessage("expiresAt must not be before notBefore");
	}

}
