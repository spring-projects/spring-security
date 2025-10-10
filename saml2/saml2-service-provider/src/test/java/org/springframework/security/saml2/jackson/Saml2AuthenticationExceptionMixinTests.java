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

package org.springframework.security.saml2.jackson;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings("removal")
class Saml2AuthenticationExceptionMixinTests {

	private JsonMapper mapper;

	@BeforeEach
	void setUp() {
		ClassLoader loader = getClass().getClassLoader();
		this.mapper = JsonMapper.builder().addModules(SecurityJacksonModules.getModules(loader)).build();
	}

	@Test
	void shouldSerialize() throws Exception {
		Saml2AuthenticationException exception = TestSaml2JsonPayloads.createDefaultSaml2AuthenticationException();

		String exceptionJson = this.mapper.writeValueAsString(exception);

		JSONAssert.assertEquals(TestSaml2JsonPayloads.DEFAULT_SAML_AUTH_EXCEPTION_JSON, exceptionJson, true);
	}

	@Test
	void shouldDeserialize() throws Exception {
		Saml2AuthenticationException exception = this.mapper
			.readValue(TestSaml2JsonPayloads.DEFAULT_SAML_AUTH_EXCEPTION_JSON, Saml2AuthenticationException.class);

		assertThat(exception).isNotNull();
		assertThat(exception.getMessage()).isEqualTo("exceptionMessage");
		assertThat(exception.getSaml2Error()).extracting(Saml2Error::getErrorCode, Saml2Error::getDescription)
			.contains("errorCode", "errorDescription");
	}

}
