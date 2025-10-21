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

package org.springframework.security.web.server.jackson;

import java.io.IOException;

import org.json.JSONException;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import tools.jackson.core.JacksonException;

import org.springframework.security.web.jackson.AbstractMixinTests;
import org.springframework.security.web.server.csrf.DefaultCsrfToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Sebastien Deleuze
 * @author Boris Finkelshteyn
 */
public class DefaultCsrfServerTokenMixinTests extends AbstractMixinTests {

	// @formatter:off
	private static final String CSRF_JSON = "{"
			+ "\"@class\": \"org.springframework.security.web.server.csrf.DefaultCsrfToken\", "
			+ "\"headerName\": \"csrf-header\", "
			+ "\"parameterName\": \"_csrf\", "
			+ "\"token\": \"1\""
			+ "}";
	// @formatter:on
	@Test
	public void defaultCsrfTokenSerializedTest() throws JacksonException, JSONException {
		DefaultCsrfToken token = new DefaultCsrfToken("csrf-header", "_csrf", "1");
		String serializedJson = this.mapper.writeValueAsString(token);
		JSONAssert.assertEquals(CSRF_JSON, serializedJson, true);
	}

	@Test
	public void defaultCsrfTokenDeserializeTest() throws IOException {
		DefaultCsrfToken token = this.mapper.readValue(CSRF_JSON, DefaultCsrfToken.class);
		assertThat(token).isNotNull();
		assertThat(token.getHeaderName()).isEqualTo("csrf-header");
		assertThat(token.getParameterName()).isEqualTo("_csrf");
		assertThat(token.getToken()).isEqualTo("1");
	}

	@Test
	public void defaultCsrfTokenDeserializeWithoutClassTest() throws IOException {
		String tokenJson = "{\"headerName\": \"csrf-header\", \"parameterName\": \"_csrf\", \"token\": \"1\"}";
		assertThatExceptionOfType(JacksonException.class)
			.isThrownBy(() -> this.mapper.readValue(tokenJson, DefaultCsrfToken.class));
	}

	@Test
	public void defaultCsrfTokenDeserializeNullValuesTest() throws IOException {
		String tokenJson = "{\"@class\": \"org.springframework.security.web.server.csrf.DefaultCsrfToken\", \"headerName\": \"\", \"parameterName\": null, \"token\": \"1\"}";
		assertThatExceptionOfType(JacksonException.class)
			.isThrownBy(() -> this.mapper.readValue(tokenJson, DefaultCsrfToken.class));
	}

}
