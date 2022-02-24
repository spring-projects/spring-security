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

package org.springframework.security.saml2.jackson2;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;

import static org.assertj.core.api.Assertions.assertThat;

class Saml2AuthenticationMixinTests {

	private ObjectMapper mapper;

	@BeforeEach
	void setUp() {
		this.mapper = new ObjectMapper();
		ClassLoader loader = getClass().getClassLoader();
		this.mapper.registerModules(SecurityJackson2Modules.getModules(loader));
	}

	@Test
	void shouldSerialize() throws Exception {
		Saml2Authentication authentication = TestSaml2JsonPayloads.createDefaultAuthentication();

		String authenticationJson = this.mapper.writeValueAsString(authentication);

		JSONAssert.assertEquals(TestSaml2JsonPayloads.DEFAULT_SAML2AUTHENTICATION_JSON, authenticationJson, true);
	}

	@Test
	void shouldDeserialize() throws Exception {
		Saml2Authentication authentication = this.mapper
				.readValue(TestSaml2JsonPayloads.DEFAULT_SAML2AUTHENTICATION_JSON, Saml2Authentication.class);

		assertThat(authentication).isNotNull();
		assertThat(authentication.getDetails()).isEqualTo(TestSaml2JsonPayloads.DETAILS);
		assertThat(authentication.getCredentials()).isEqualTo(TestSaml2JsonPayloads.SAML_RESPONSE);
		assertThat(authentication.getSaml2Response()).isEqualTo(TestSaml2JsonPayloads.SAML_RESPONSE);
		assertThat(authentication.getAuthorities()).isEqualTo(TestSaml2JsonPayloads.AUTHORITIES);
		assertThat(authentication.getPrincipal()).usingRecursiveComparison()
				.isEqualTo(TestSaml2JsonPayloads.createDefaultPrincipal());
		assertThat(authentication.getDetails()).usingRecursiveComparison().isEqualTo(TestSaml2JsonPayloads.DETAILS);
	}

}
