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

package org.springframework.security.oauth2.client.jackson2;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link OAuth2AuthenticationExceptionMixin}.
 *
 * @author Dennis Neufeld
 * @since 5.3.4
 */
@SuppressWarnings("removal")
public class OAuth2AuthenticationExceptionMixinTests {

	private ObjectMapper mapper;

	@BeforeEach
	public void setup() {
		ClassLoader loader = getClass().getClassLoader();
		this.mapper = new ObjectMapper();
		this.mapper.registerModules(SecurityJackson2Modules.getModules(loader));
	}

	@Test
	public void serializeWhenMixinRegisteredThenSerializes() throws Exception {
		OAuth2AuthenticationException exception = new OAuth2AuthenticationException(
				new OAuth2Error("[authorization_request_not_found]", "Authorization Request Not Found", "/foo/bar"),
				"Authorization Request Not Found");
		String serializedJson = this.mapper.writeValueAsString(exception);
		String expected = asJson(exception);
		JSONAssert.assertEquals(expected, serializedJson, true);
	}

	@Test
	public void serializeWhenRequiredAttributesOnlyThenSerializes() throws Exception {
		OAuth2AuthenticationException exception = new OAuth2AuthenticationException(
				new OAuth2Error("[authorization_request_not_found]"));
		String serializedJson = this.mapper.writeValueAsString(exception);
		String expected = asJson(exception);
		JSONAssert.assertEquals(expected, serializedJson, true);
	}

	@Test
	public void deserializeWhenMixinNotRegisteredThenThrowJsonProcessingException() {
		String json = asJson(new OAuth2AuthenticationException(new OAuth2Error("[authorization_request_not_found]")));
		assertThatExceptionOfType(JsonProcessingException.class)
			.isThrownBy(() -> new ObjectMapper().readValue(json, OAuth2AuthenticationException.class));
	}

	@Test
	public void deserializeWhenMixinRegisteredThenDeserializes() throws Exception {
		OAuth2AuthenticationException expected = new OAuth2AuthenticationException(
				new OAuth2Error("[authorization_request_not_found]", "Authorization Request Not Found", "/foo/bar"),
				"Authorization Request Not Found");
		OAuth2AuthenticationException exception = this.mapper.readValue(asJson(expected),
				OAuth2AuthenticationException.class);
		assertThat(exception).isNotNull();
		assertThat(exception.getCause()).isNull();
		assertThat(exception.getMessage()).isEqualTo(expected.getMessage());
		OAuth2Error oauth2Error = exception.getError();
		assertThat(oauth2Error).isNotNull();
		assertThat(oauth2Error.getErrorCode()).isEqualTo(expected.getError().getErrorCode());
		assertThat(oauth2Error.getDescription()).isEqualTo(expected.getError().getDescription());
		assertThat(oauth2Error.getUri()).isEqualTo(expected.getError().getUri());
	}

	@Test
	public void deserializeWhenRequiredAttributesOnlyThenDeserializes() throws Exception {
		OAuth2AuthenticationException expected = new OAuth2AuthenticationException(
				new OAuth2Error("[authorization_request_not_found]"));
		OAuth2AuthenticationException exception = this.mapper.readValue(asJson(expected),
				OAuth2AuthenticationException.class);
		assertThat(exception).isNotNull();
		assertThat(exception.getCause()).isNull();
		assertThat(exception.getMessage()).isNull();
		OAuth2Error oauth2Error = exception.getError();
		assertThat(oauth2Error).isNotNull();
		assertThat(oauth2Error.getErrorCode()).isEqualTo(expected.getError().getErrorCode());
		assertThat(oauth2Error.getDescription()).isNull();
		assertThat(oauth2Error.getUri()).isNull();
	}

	private String asJson(OAuth2AuthenticationException exception) {
		OAuth2Error error = exception.getError();
		// @formatter:off
		return "\n{"
				+ "\n  \"@class\": \"org.springframework.security.oauth2.core.OAuth2AuthenticationException\","
				+ "\n  \"error\":"
				+ "\n  {"
				+ "\n    \"@class\":\"org.springframework.security.oauth2.core.OAuth2Error\","
				+ "\n    \"errorCode\":\"" + error.getErrorCode() + "\","
				+ "\n    \"description\":" + jsonStringOrNull(error.getDescription()) + ","
				+ "\n    \"uri\":" + jsonStringOrNull(error.getUri())
				+ "\n  },"
				+ "\n  \"detailMessage\":" + jsonStringOrNull(exception.getMessage())
				+ "\n}";
		// @formatter:on
	}

	private String jsonStringOrNull(String input) {
		return (input != null) ? "\"" + input + "\"" : "null";
	}

}
