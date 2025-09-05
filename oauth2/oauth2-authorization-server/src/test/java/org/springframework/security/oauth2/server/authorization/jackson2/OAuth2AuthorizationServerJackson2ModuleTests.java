/*
 * Copyright 2020-2024 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.jackson2;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2AuthorizationServerJackson2Module}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2AuthorizationServerJackson2ModuleTests {

	private static final TypeReference<Map<String, Object>> STRING_OBJECT_MAP = new TypeReference<>() {
	};

	private static final TypeReference<Set<String>> STRING_SET = new TypeReference<>() {
	};

	private static final TypeReference<String[]> STRING_ARRAY = new TypeReference<>() {
	};

	private ObjectMapper objectMapper;

	@BeforeEach
	public void setup() {
		this.objectMapper = new ObjectMapper();
		this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
	}

	@Test
	public void readValueWhenUnmodifiableMapThenSuccess() throws Exception {
		Map<String, Object> map = Collections.unmodifiableMap(new HashMap<>(Collections.singletonMap("key", "value")));
		String json = this.objectMapper.writeValueAsString(map);
		assertThat(this.objectMapper.readValue(json, STRING_OBJECT_MAP)).isEqualTo(map);
	}

	@Test
	public void readValueWhenHashSetThenSuccess() throws Exception {
		Set<String> set = new HashSet<>(Arrays.asList("one", "two"));
		String json = this.objectMapper.writeValueAsString(set);
		assertThat(this.objectMapper.readValue(json, STRING_SET)).isEqualTo(set);
	}

	// gh-457
	@Test
	public void readValueWhenLinkedHashSetThenSuccess() throws Exception {
		Set<String> set = new LinkedHashSet<>(Arrays.asList("one", "two"));
		String json = this.objectMapper.writeValueAsString(set);
		assertThat(this.objectMapper.readValue(json, STRING_SET)).isEqualTo(set);
	}

	// gh-1666
	@Test
	public void readValueWhenStringArrayThenSuccess() throws Exception {
		String[] array = new String[] { "one", "two" };
		String json = this.objectMapper.writeValueAsString(array);
		assertThat(this.objectMapper.readValue(json, STRING_ARRAY)).isEqualTo(array);
	}

}
