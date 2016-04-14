/*
 * Copyright 2015-2016 the original author or authors.
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

package org.springframework.security.jackson2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;

import static org.assertj.core.api.Assertions.*;

/**
 * @author Jitendra Singh.
 */
public class SimpleGrantedAuthorityMixinTest {

	ObjectMapper mapper;

	@Before
	public void setup() {
		mapper = new ObjectMapper();
		mapper.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class);
	}

	@Test
	public void serializeSimpleGrantedAuthorityTest() throws JsonProcessingException, JSONException {
		SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");
		String serializeJson = mapper.writeValueAsString(authority);
		String expectedJson = "{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}";
		JSONAssert.assertEquals(expectedJson, serializeJson, true);
	}

	@Test
	public void deserializeGrantedAuthorityTest() throws IOException {
		String json = "{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\", \"role\": \"ROLE_USER\"}";
		SimpleGrantedAuthority authority = mapper.readValue(json, SimpleGrantedAuthority.class);
		assertThat(authority).isNotNull();
		assertThat(authority.getAuthority()).isNotNull().isEqualTo("ROLE_USER");
	}

	@Test(expected = JsonMappingException.class)
	public void deserializeGrantedAuthorityWithoutRoleTest() throws IOException {
		String json = "{\"@class\": \"org.springframework.security.core.authority.SimpleGrantedAuthority\"}";
		mapper.readValue(json, SimpleGrantedAuthority.class);
	}
}
