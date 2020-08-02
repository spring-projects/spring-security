/*
 * Copyright 2002-2018 the original author or authors.
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

import java.io.IOException;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.json.JSONException;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.security.authentication.BadCredentialsException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Yannick Lombardi
 * @since 5.0
 */
public class BadCredentialsExceptionMixinTests extends AbstractMixinTests {

	// @formatter:off
	private static final String EXCEPTION_JSON = "{"
		+ "\"@class\": \"org.springframework.security.authentication.BadCredentialsException\","
		+ "\"localizedMessage\": \"message\", "
		+ "\"message\": \"message\", "
		+ "\"suppressed\": [\"[Ljava.lang.Throwable;\",[]]"
		+ "}";
	// @formatter:on
	@Test
	public void serializeBadCredentialsExceptionMixinTest() throws JsonProcessingException, JSONException {
		BadCredentialsException exception = new BadCredentialsException("message");
		String serializedJson = this.mapper.writeValueAsString(exception);
		JSONAssert.assertEquals(EXCEPTION_JSON, serializedJson, true);
	}

	@Test
	public void deserializeBadCredentialsExceptionMixinTest() throws IOException {
		BadCredentialsException exception = this.mapper.readValue(EXCEPTION_JSON, BadCredentialsException.class);
		assertThat(exception).isNotNull();
		assertThat(exception.getCause()).isNull();
		assertThat(exception.getMessage()).isEqualTo("message");
		assertThat(exception.getLocalizedMessage()).isEqualTo("message");
	}

}
