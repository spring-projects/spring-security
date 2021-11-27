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

package org.springframework.security.oauth2.core;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.Assertions.assertThatObject;

/**
 * Tests for {@link ClaimAccessor}.
 *
 * @author Joe Grandja
 */
public class ClaimAccessorTests {

	private Map<String, Object> claims = new HashMap<>();

	private ClaimAccessor claimAccessor = (() -> this.claims);

	@BeforeEach
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
	public void getClaimAsBooleanWhenBooleanTypeThenReturnBoolean() {
		Boolean expectedClaimValue = Boolean.TRUE;
		String claimName = "boolean";
		this.claims.put(claimName, expectedClaimValue);
		assertThat(this.claimAccessor.getClaimAsBoolean(claimName)).isEqualTo(expectedClaimValue);
	}

	@Test
	public void getClaimAsBooleanWhenStringTypeThenReturnBoolean() {
		Boolean expectedClaimValue = Boolean.TRUE;
		String claimName = "boolean";
		this.claims.put(claimName, expectedClaimValue.toString());
		assertThat(this.claimAccessor.getClaimAsBoolean(claimName)).isEqualTo(expectedClaimValue);
	}

	// gh-10148
	@Test
	public void getClaimAsBooleanWhenNonBooleanTypeThenThrowIllegalArgumentException() {
		String claimName = "boolean";
		Map<Object, Object> claimValue = new HashMap<>();
		this.claims.put(claimName, claimValue);
		assertThatIllegalArgumentException().isThrownBy(() -> this.claimAccessor.getClaimAsBoolean(claimName))
				.withMessage("Unable to convert claim '" + claimName + "' of type '" + claimValue.getClass()
						+ "' to Boolean.");
	}

	@Test
	public void getClaimAsMapWhenNotExistingThenReturnNull() {
		assertThat(this.claimAccessor.getClaimAsMap("map")).isNull();
	}

	@Test
	public void getClaimAsMapWhenMapTypeThenReturnMap() {
		Map<Object, Object> expectedClaimValue = Collections.emptyMap();
		String claimName = "map";
		this.claims.put(claimName, expectedClaimValue);
		assertThat(this.claimAccessor.getClaimAsMap(claimName)).isEqualTo(expectedClaimValue);
	}

	@Test
	public void getClaimAsMapWhenValueIsNullThenThrowNullPointerException() {
		String claimName = "map";
		this.claims.put(claimName, null);
		assertThatNullPointerException().isThrownBy(() -> this.claimAccessor.getClaimAsMap(claimName));
	}

	@Test
	public void getClaimAsMapWhenNonMapTypeThenThrowIllegalArgumentException() {
		String claimName = "map";
		this.claims.put(claimName, "map");
		assertThatIllegalArgumentException().isThrownBy(() -> this.claimAccessor.getClaimAsMap(claimName));
	}

	@Test
	public void getClaimAsStringListWhenNotExistingThenReturnNull() {
		assertThat(this.claimAccessor.getClaimAsStringList("list")).isNull();
	}

	@Test
	public void getClaimAsStringListWhenStringListTypeThenReturnList() {
		List<String> expectedClaimValue = Collections.emptyList();
		String claimName = "list";
		this.claims.put(claimName, expectedClaimValue);
		assertThat(this.claimAccessor.getClaimAsStringList(claimName)).isEqualTo(expectedClaimValue);
	}

	@Test
	public void getClaimAsStringListWhenNonListTypeThenReturnList() {
		List<String> expectedClaimValue = Collections.singletonList("list");
		String claimName = "list";
		this.claims.put(claimName, expectedClaimValue.get(0));
		assertThat(this.claimAccessor.getClaimAsStringList(claimName)).isEqualTo(expectedClaimValue);
	}

	@Test
	public void getClaimAsStringListWhenValueIsNullThenNullPointerException() {
		String claimName = "list";
		this.claims.put(claimName, null);
		assertThatNullPointerException().isThrownBy(() -> this.claimAccessor.getClaimAsStringList(claimName));
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
		assertThatObject(this.claimAccessor.getClaim(claimName)).isNotInstanceOf(Boolean.class);
	}

}
