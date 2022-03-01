/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.jackson2;

import java.util.Collections;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import static org.assertj.core.api.Assertions.assertThat;

class UnmodifiableMapDeserializerTests extends AbstractMixinTests {

	// @formatter:off
	private static final String DEFAULT_MAP_JSON = "{"
			+ "\"@class\": \"java.util.Collections$UnmodifiableMap\","
			+ "\"Key\": \"Value\""
			+ "}";
	// @formatter:on

	@Test
	void shouldSerialize() throws Exception {
		String mapJson = mapper
				.writeValueAsString(Collections.unmodifiableMap(Collections.singletonMap("Key", "Value")));

		JSONAssert.assertEquals(DEFAULT_MAP_JSON, mapJson, true);
	}

	@Test
	void shouldDeserialize() throws Exception {
		Map<String, String> map = mapper.readValue(DEFAULT_MAP_JSON,
				Collections.unmodifiableMap(Collections.emptyMap()).getClass());

		assertThat(map).isNotNull().isInstanceOf(Collections.unmodifiableMap(Collections.emptyMap()).getClass())
				.containsAllEntriesOf(Collections.singletonMap("Key", "Value"));
	}

}
