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

package org.springframework.security.web.jackson2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.security.web.csrf.DefaultCsrfToken;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Jitendra Singh
 */
@RunWith(MockitoJUnitRunner.class)
public class DefaultCsrfTokenMixinTests {

	ObjectMapper objectMapper;
	String defaultCsrfTokenJson;

	@Before
	public void setup() {
		objectMapper = new ObjectMapper();
		objectMapper.addMixIn(DefaultCsrfToken.class, DefaultCsrfTokenMixin.class);
		defaultCsrfTokenJson = "{\"@class\": \"org.springframework.security.web.csrf.DefaultCsrfToken\", " +
				"\"headerName\": \"csrf-header\", \"parameterName\": \"_csrf\", \"token\": \"1\"}";
	}

	@Test
	public void defaultCsrfTokenSerializedTest() throws JsonProcessingException, JSONException {
		DefaultCsrfToken token = new DefaultCsrfToken("csrf-header", "_csrf", "1");
		String serializedJson = objectMapper.writeValueAsString(token);
		JSONAssert.assertEquals(defaultCsrfTokenJson, serializedJson, true);
	}

	@Test
	public void defaultCsrfTokenDeserializeTest() throws IOException {
		DefaultCsrfToken token = objectMapper.readValue(defaultCsrfTokenJson, DefaultCsrfToken.class);
		assertThat(token).isNotNull();
		assertThat(token.getHeaderName()).isEqualTo("csrf-header");
		assertThat(token.getParameterName()).isEqualTo("_csrf");
		assertThat(token.getToken()).isEqualTo("1");
	}

	@Test(expected = JsonMappingException.class)
	public void defaultCsrfTokenDeserializeWithoutClassTest() throws IOException {
		String tokenJson = "{\"headerName\": \"csrf-header\", \"parameterName\": \"_csrf\", \"token\": \"1\"}";
		objectMapper.readValue(tokenJson, DefaultCsrfToken.class);
	}

	@Test(expected = JsonMappingException.class)
	public void defaultCsrfTokenDeserializeNullValuesTest() throws IOException {
		String tokenJson = "{\"@class\": \"org.springframework.security.web.csrf.DefaultCsrfToken\", \"headerName\": \"\", \"parameterName\": null, \"token\": \"1\"}";
		objectMapper.readValue(tokenJson, DefaultCsrfToken.class);
	}
}
