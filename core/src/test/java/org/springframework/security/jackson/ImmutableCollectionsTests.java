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

package org.springframework.security.jackson;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import tools.jackson.core.type.TypeReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests that the JDK immutable collections created by {@code List.of}, {@code Set.of},
 * {@code Map.of} and {@code Stream.toList()} can be serialized and deserialized.
 *
 * @author Rajesh Vasa
 */
class ImmutableCollectionsTests extends AbstractMixinTests {

	private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {
	};

	@Test
	void listOfOneElementWhenRoundTripThenDeserialized() throws Exception {
		assertRoundTrip(List.of("a"));
	}

	@Test
	void listOfManyElementsWhenRoundTripThenDeserialized() throws Exception {
		assertRoundTrip(List.of("a", "b", "c"));
	}

	@Test
	void emptyListOfWhenRoundTripThenDeserialized() throws Exception {
		assertRoundTrip(List.of());
	}

	@Test
	void streamToListWhenRoundTripThenDeserialized() throws Exception {
		assertRoundTrip(Stream.of("ROLE_USER", "ROLE_ADMIN").toList());
	}

	@Test
	void setOfOneElementWhenRoundTripThenDeserialized() throws Exception {
		assertRoundTrip(Set.of("a"));
	}

	@Test
	void setOfManyElementsWhenRoundTripThenDeserialized() throws Exception {
		assertRoundTrip(Set.of("a", "b", "c"));
	}

	@Test
	void mapOfOneEntryWhenRoundTripThenDeserialized() throws Exception {
		assertRoundTrip(Map.of("k", "v"));
	}

	@Test
	void mapOfManyEntriesWhenRoundTripThenDeserialized() throws Exception {
		assertRoundTrip(Map.of("k1", "v1", "k2", "v2"));
	}

	private void assertRoundTrip(Object value) throws Exception {
		Map<String, Object> claims = new HashMap<>();
		claims.put("value", value);
		String json = this.mapper.writeValueAsString(claims);
		Map<String, Object> deserialized = this.mapper.readValue(json, MAP_TYPE);
		assertThat(deserialized.get("value")).isEqualTo(value);
	}

}
