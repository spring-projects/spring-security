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
 * @author Donghwan Kim
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
		Instant issuedAt = Instant.parse("2025-01-01T00:00:00Z");
		Instant notBefore = Instant.parse("2025-01-01T00:01:00Z");
		Instant expiresAt = Instant.parse("2025-01-01T00:05:00Z");

		TimestampedGrantedAuthority authority = TimestampedGrantedAuthority.withAuthority("profile:read")
			.issuedAt(issuedAt)
			.notBefore(notBefore)
			.expiresAt(expiresAt)
			.build();

		assertThat(authority.getAuthority()).isEqualTo("profile:read");
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
	public void issuedAtWhenNullThenThrowsException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> TimestampedGrantedAuthority.withAuthority("profile:read").issuedAt(null))
			.withMessage("issuedAt cannot be null");
	}

	@Test
	public void notBeforeWhenNullThenThrowsException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> TimestampedGrantedAuthority.withAuthority("profile:read").notBefore(null))
			.withMessage("notBefore cannot be null");
	}

	@Test
	public void expiresAtWhenNullThenThrowsException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> TimestampedGrantedAuthority.withAuthority("profile:read").expiresAt(null))
			.withMessage("expiresAt cannot be null");
	}

	@Test
	public void buildWhenNotBeforeAfterExpiresAtThenThrowsException() {
		Instant notBefore = Instant.parse("2025-01-01T00:05:00Z");
		Instant expiresAt = Instant.parse("2025-01-01T00:01:00Z");

		assertThatIllegalArgumentException()
			.isThrownBy(() -> TimestampedGrantedAuthority.withAuthority("profile:read")
				.notBefore(notBefore)
				.expiresAt(expiresAt)
				.build())
			.withMessage("notBefore cannot be after expiresAt");
	}

	@Test
	public void equalsWhenSameValuesThenEqual() {
		Instant issuedAt = Instant.parse("2025-01-01T00:00:00Z");
		Instant notBefore = Instant.parse("2025-01-01T00:01:00Z");
		Instant expiresAt = Instant.parse("2025-01-01T00:05:00Z");

		TimestampedGrantedAuthority authority = TimestampedGrantedAuthority.withAuthority("profile:read")
			.issuedAt(issuedAt)
			.notBefore(notBefore)
			.expiresAt(expiresAt)
			.build();

		TimestampedGrantedAuthority other = TimestampedGrantedAuthority.withAuthority("profile:read")
			.issuedAt(issuedAt)
			.notBefore(notBefore)
			.expiresAt(expiresAt)
			.build();

		assertThat(authority).isEqualTo(other);
		assertThat(authority).hasSameHashCodeAs(other);
	}

	@Test
	public void toStringWhenInvokedThenIncludesFields() {
		Instant issuedAt = Instant.parse("2025-01-01T00:00:00Z");
		TimestampedGrantedAuthority authority = TimestampedGrantedAuthority.withAuthority("profile:read")
			.issuedAt(issuedAt)
			.build();

		assertThat(authority.toString()).isEqualTo(
				"TimestampedGrantedAuthority [authority=profile:read, issuedAt=2025-01-01T00:00:00Z, notBefore=null, expiresAt=null]");
	}

}
