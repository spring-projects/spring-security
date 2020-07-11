/*
 * Copyright 2002-2020 the original author or authors.
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
import java.io.IOException;
import org.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2AuthenticationExceptionMixin}.
 *
 * @author Dennis Neufeld
 * @since 5.4
 */
public class OAuth2AuthenticationExceptionMixinTests {

	private ObjectMapper mapper;

	@Before
	public void setup() {
		ClassLoader loader = getClass().getClassLoader();
		this.mapper = new ObjectMapper();
		this.mapper.registerModules(SecurityJackson2Modules.getModules(loader));
	}

	// @formatter:off
	private static final String EXCEPTION_JSON
			= "\n{"
			+ "\n  \"@class\": \"org.springframework.security.oauth2.core.OAuth2AuthenticationException\","
			+ "\n  \"error\":"
			+ "\n  {"
			+ "\n    \"@class\":\"org.springframework.security.oauth2.core.OAuth2Error\","
			+ "\n    \"errorCode\":\"authorization_request_not_found\","
			+ "\n    \"description\":null,"
			+ "\n    \"uri\":null"
			+ "\n  },"
			+ "\n  \"message\":\"[authorization_request_not_found] \","
			+ "\n  \"suppressed\":[\"[Ljava.lang.Throwable;\",[]],"
			+ "\n  \"localizedMessage\":\"[authorization_request_not_found] \""
			+ "\n}";
	// @formatter:on

	@Test
	public void serializeOAuth2AuthenticationExceptionMixinTest() throws JsonProcessingException, JSONException {
		OAuth2Error oauth2Error = new OAuth2Error("authorization_request_not_found");
		OAuth2AuthenticationException exception = new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		String serializedJson = mapper.writeValueAsString(exception);
		JSONAssert.assertEquals(EXCEPTION_JSON, serializedJson, true);
	}

	@Test
	public void deserializeOAuth2AuthenticationExceptionMixinTest() throws IOException {
		OAuth2AuthenticationException exception = mapper.readValue(EXCEPTION_JSON, OAuth2AuthenticationException.class);
		assertThat(exception).isNotNull();
		assertThat(exception.getCause()).isNull();
		assertThat(exception.getMessage()).isEqualTo("[authorization_request_not_found] ");
		assertThat(exception.getLocalizedMessage()).isEqualTo("[authorization_request_not_found] ");

		OAuth2Error oauth2Error = exception.getError();
		assertThat(oauth2Error).isNotNull();
		assertThat(oauth2Error.getErrorCode()).isEqualTo("authorization_request_not_found");
		assertThat(oauth2Error.getDescription()).isNull();
		assertThat(oauth2Error.getUri()).isNull();
	}

}
