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
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;

import static org.assertj.core.api.Assertions.assertThat;

class DefaultSaml2AuthenticatedPrincipalMixinTests {

	private ObjectMapper mapper;

	@BeforeEach
	void setUp() {
		this.mapper = new ObjectMapper();
		ClassLoader loader = getClass().getClassLoader();
		this.mapper.registerModules(SecurityJackson2Modules.getModules(loader));
	}

	@Test
	void shouldSerialize() throws Exception {
		DefaultSaml2AuthenticatedPrincipal principal = TestSaml2JsonPayloads.createDefaultPrincipal();

		String principalJson = this.mapper.writeValueAsString(principal);

		JSONAssert.assertEquals(TestSaml2JsonPayloads.DEFAULT_AUTHENTICATED_PRINCIPAL_JSON, principalJson, true);
	}

	@Test
	void shouldSerializeWithoutRegistrationId() throws Exception {
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal(
				TestSaml2JsonPayloads.PRINCIPAL_NAME, TestSaml2JsonPayloads.ATTRIBUTES,
				TestSaml2JsonPayloads.SESSION_INDEXES);

		String principalJson = this.mapper.writeValueAsString(principal);

		JSONAssert.assertEquals(principalWithoutRegId(), principalJson, true);
	}

	@Test
	void shouldSerializeWithoutIndices() throws Exception {
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal(
				TestSaml2JsonPayloads.PRINCIPAL_NAME, TestSaml2JsonPayloads.ATTRIBUTES);
		principal.setRelyingPartyRegistrationId(TestSaml2JsonPayloads.REG_ID);

		String principalJson = this.mapper.writeValueAsString(principal);

		JSONAssert.assertEquals(principalWithoutIndices(), principalJson, true);
	}

	@Test
	void shouldDeserialize() throws Exception {
		DefaultSaml2AuthenticatedPrincipal principal = this.mapper.readValue(
				TestSaml2JsonPayloads.DEFAULT_AUTHENTICATED_PRINCIPAL_JSON, DefaultSaml2AuthenticatedPrincipal.class);

		assertThat(principal).isNotNull();
		assertThat(principal.getName()).isEqualTo(TestSaml2JsonPayloads.PRINCIPAL_NAME);
		assertThat(principal.getRelyingPartyRegistrationId()).isEqualTo(TestSaml2JsonPayloads.REG_ID);
		assertThat(principal.getAttributes()).isEqualTo(TestSaml2JsonPayloads.ATTRIBUTES);
		assertThat(principal.getSessionIndexes()).isEqualTo(TestSaml2JsonPayloads.SESSION_INDEXES);
	}

	@Test
	void shouldDeserializeWithoutRegistrationId() throws Exception {
		DefaultSaml2AuthenticatedPrincipal principal = this.mapper.readValue(principalWithoutRegId(),
				DefaultSaml2AuthenticatedPrincipal.class);

		assertThat(principal).isNotNull();
		assertThat(principal.getName()).isEqualTo(TestSaml2JsonPayloads.PRINCIPAL_NAME);
		assertThat(principal.getRelyingPartyRegistrationId()).isNull();
		assertThat(principal.getAttributes()).isEqualTo(TestSaml2JsonPayloads.ATTRIBUTES);
		assertThat(principal.getSessionIndexes()).isEqualTo(TestSaml2JsonPayloads.SESSION_INDEXES);
	}

	private static String principalWithoutRegId() {
		return TestSaml2JsonPayloads.DEFAULT_AUTHENTICATED_PRINCIPAL_JSON.replace(TestSaml2JsonPayloads.REG_ID_JSON,
				"null");
	}

	private static String principalWithoutIndices() {
		return TestSaml2JsonPayloads.DEFAULT_AUTHENTICATED_PRINCIPAL_JSON
				.replace(TestSaml2JsonPayloads.SESSION_INDEXES_JSON, "[\"java.util.Collections$EmptyList\", []]");
	}

}
