/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.oauth2.core;

import org.junit.Before;
import org.junit.Test;

import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

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

		assertThat(this.claimAccessor.getClaimAsInstant(claimName)).isBetween(expectedClaimValue.minusSeconds(1),
				expectedClaimValue.plusSeconds(1));
	}

	// gh-5191
	@Test
	public void getClaimAsInstantWhenLongTypeSecondsThenReturnInstant() {
		Instant expectedClaimValue = Instant.now();
		String claimName = "longSeconds";
		this.claims.put(claimName, expectedClaimValue.getEpochSecond());

		assertThat(this.claimAccessor.getClaimAsInstant(claimName)).isBetween(expectedClaimValue.minusSeconds(1),
				expectedClaimValue.plusSeconds(1));
	}

	@Test
	public void getClaimAsInstantWhenInstantTypeThenReturnInstant() {
		Instant expectedClaimValue = Instant.now();
		String claimName = "instant";
		this.claims.put(claimName, expectedClaimValue);

		assertThat(this.claimAccessor.getClaimAsInstant(claimName)).isBetween(expectedClaimValue.minusSeconds(1),
				expectedClaimValue.plusSeconds(1));
	}

	// gh-5250
	@Test
	public void getClaimAsInstantWhenIntegerTypeSecondsThenReturnInstant() {
		Instant expectedClaimValue = Instant.now();
		String claimName = "integerSeconds";
		this.claims.put(claimName, Long.valueOf(expectedClaimValue.getEpochSecond()).intValue());

		assertThat(this.claimAccessor.getClaimAsInstant(claimName)).isBetween(expectedClaimValue.minusSeconds(1),
				expectedClaimValue.plusSeconds(1));
	}

	// gh-5250
	@Test
	public void getClaimAsInstantWhenDoubleTypeSecondsThenReturnInstant() {
		Instant expectedClaimValue = Instant.now();
		String claimName = "doubleSeconds";
		this.claims.put(claimName, Long.valueOf(expectedClaimValue.getEpochSecond()).doubleValue());

		assertThat(this.claimAccessor.getClaimAsInstant(claimName)).isBetween(expectedClaimValue.minusSeconds(1),
				expectedClaimValue.plusSeconds(1));
	}

	// gh-5608
	@Test
	public void getClaimAsStringWhenValueIsNullThenReturnNull() {
		String claimName = "claim-with-null-value";
		this.claims.put(claimName, null);

		assertThat(this.claimAccessor.getClaimAsString(claimName)).isNull();
	}

	@Test
	public void getClaimWhenNotExistingThenReturnNull() {
		String claimName = "list";
		List<String> actualClaimValue = this.claimAccessor.getClaim(claimName);
		assertThat(actualClaimValue).isNull();
	}

	@Test
	public void getClaimWhenValueIsConvertedThenReturnList() {
		List<String> expectedClaimValue = Arrays.asList("item1", "item2");
		String claimName = "list";
		this.claims.put(claimName, expectedClaimValue);

		List<String> actualClaimValue = this.claimAccessor.getClaim(claimName);

		assertThat(actualClaimValue).containsOnlyElementsOf(expectedClaimValue);
	}

	@Test
	public void getClaimWhenValueIsConvertedThenReturnBoolean() {
		boolean expectedClaimValue = true;
		String claimName = "boolean";
		this.claims.put(claimName, expectedClaimValue);

		boolean actualClaimValue = this.claimAccessor.getClaim(claimName);

		assertThat(actualClaimValue).isEqualTo(expectedClaimValue);
	}

	@Test
	public void getClaimWhenValueIsNotConvertedThenThrowClassCastException() {
		String expectedClaimValue = "true";
		String claimName = "boolean";
		this.claims.put(claimName, expectedClaimValue);

		Throwable thrown = catchThrowable(() -> {
			boolean actualClaimValue = this.claimAccessor.getClaim(claimName);
		});

		assertThat(thrown).isInstanceOf(ClassCastException.class);
	}

}
