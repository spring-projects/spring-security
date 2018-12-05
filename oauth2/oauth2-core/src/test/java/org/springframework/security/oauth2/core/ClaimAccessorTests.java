/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.oauth2.core;

import org.junit.Before;
import org.junit.Test;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ClaimAccessor}.
 *
 * @author Joe Grandja
 */
public class ClaimAccessorTests {
	private Map<String, Object> claims = new HashMap<>();
	private ClaimAccessor claimAccessor = (() -> this.claims);

	@Before
	public void setup() {
		this.claims.clear();
	}

	// gh-5192
	@Test
	public void getClaimAsInstantWhenDateTypeThenReturnInstant() {
		Instant expectedClaimValue = Instant.now();
		String claimName = "date";
		this.claims.put(claimName, Date.from(expectedClaimValue));

		assertThat(this.claimAccessor.getClaimAsInstant(claimName)).isBetween(
				expectedClaimValue.minusSeconds(1), expectedClaimValue.plusSeconds(1));
	}

	// gh-5191
	@Test
	public void getClaimAsInstantWhenLongTypeSecondsThenReturnInstant() {
		Instant expectedClaimValue = Instant.now();
		String claimName = "longSeconds";
		this.claims.put(claimName, expectedClaimValue.getEpochSecond());

		assertThat(this.claimAccessor.getClaimAsInstant(claimName)).isBetween(
				expectedClaimValue.minusSeconds(1), expectedClaimValue.plusSeconds(1));
	}

	@Test
	public void getClaimAsInstantWhenInstantTypeThenReturnInstant() {
		Instant expectedClaimValue = Instant.now();
		String claimName = "instant";
		this.claims.put(claimName, expectedClaimValue);

		assertThat(this.claimAccessor.getClaimAsInstant(claimName)).isBetween(
				expectedClaimValue.minusSeconds(1), expectedClaimValue.plusSeconds(1));
	}

	// gh-5250
	@Test
	public void getClaimAsInstantWhenIntegerTypeSecondsThenReturnInstant() {
		Instant expectedClaimValue = Instant.now();
		String claimName = "integerSeconds";
		this.claims.put(claimName, Long.valueOf(expectedClaimValue.getEpochSecond()).intValue());

		assertThat(this.claimAccessor.getClaimAsInstant(claimName)).isBetween(
				expectedClaimValue.minusSeconds(1), expectedClaimValue.plusSeconds(1));
	}

	// gh-5250
	@Test
	public void getClaimAsInstantWhenDoubleTypeSecondsThenReturnInstant() {
		Instant expectedClaimValue = Instant.now();
		String claimName = "doubleSeconds";
		this.claims.put(claimName, Long.valueOf(expectedClaimValue.getEpochSecond()).doubleValue());

		assertThat(this.claimAccessor.getClaimAsInstant(claimName)).isBetween(
				expectedClaimValue.minusSeconds(1), expectedClaimValue.plusSeconds(1));
	}

	// gh-6187
	@Test
	public void getClaimAsInstantWhenISODateStringThenReturnInstant() {
		Instant expectedClaimValue = Instant.parse("2011-12-03T09:15:30Z");
		String claimName = "isoDate";

		this.claims.put(claimName, "2011-12-03T09:15:30Z");
		assertThat(this.claimAccessor.getClaimAsInstant(claimName)).isBetween(
				expectedClaimValue.minusSeconds(1), expectedClaimValue.plusSeconds(1));
		this.claims.put(claimName, "2011-12-03T10:15:30+01:00");
		assertThat(this.claimAccessor.getClaimAsInstant(claimName)).isBetween(
				expectedClaimValue.minusSeconds(1), expectedClaimValue.plusSeconds(1));
		this.claims.put(claimName, "2011-12-03T10:15:30+01:00[Europe/Paris]");
		assertThat(this.claimAccessor.getClaimAsInstant(claimName)).isBetween(
				expectedClaimValue.minusSeconds(1), expectedClaimValue.plusSeconds(1));
	}

	// gh-6187
	@Test(expected = IllegalArgumentException.class)
	public void getClaimAsInstantWithoutTimezoneThrowsIAE() {
		String claimName = "isoDate";
		this.claims.put(claimName, "2011-12-03T09:15:30");
		this.claimAccessor.getClaimAsInstant(claimName);
	}

	// gh-5608
	@Test
	public void getClaimAsStringWhenValueIsNullThenReturnNull() {
		String claimName = "claim-with-null-value";
		this.claims.put(claimName, null);

		assertThat(this.claimAccessor.getClaimAsString(claimName)).isNull();
	}
}
