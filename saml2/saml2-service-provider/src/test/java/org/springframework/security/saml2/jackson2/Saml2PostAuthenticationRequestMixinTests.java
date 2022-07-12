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
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;

import static org.assertj.core.api.Assertions.assertThat;

class Saml2PostAuthenticationRequestMixinTests {

	private ObjectMapper mapper;

	@BeforeEach
	void setUp() {
		this.mapper = new ObjectMapper();
		ClassLoader loader = getClass().getClassLoader();
		this.mapper.registerModules(SecurityJackson2Modules.getModules(loader));
	}

	@Test
	void shouldSerialize() throws Exception {
		Saml2PostAuthenticationRequest request = TestSaml2JsonPayloads.createDefaultSaml2PostAuthenticationRequest();

		String requestJson = this.mapper.writeValueAsString(request);

		JSONAssert.assertEquals(TestSaml2JsonPayloads.DEFAULT_POST_AUTH_REQUEST_JSON, requestJson, true);
	}

	@Test
	void shouldDeserialize() throws Exception {
		Saml2PostAuthenticationRequest authRequest = this.mapper
				.readValue(TestSaml2JsonPayloads.DEFAULT_POST_AUTH_REQUEST_JSON, Saml2PostAuthenticationRequest.class);

		assertThat(authRequest).isNotNull();
		assertThat(authRequest.getSamlRequest()).isEqualTo(TestSaml2JsonPayloads.SAML_REQUEST);
		assertThat(authRequest.getRelayState()).isEqualTo(TestSaml2JsonPayloads.RELAY_STATE);
		assertThat(authRequest.getAuthenticationRequestUri())
				.isEqualTo(TestSaml2JsonPayloads.AUTHENTICATION_REQUEST_URI);
		assertThat(authRequest.getRelyingPartyRegistrationId())
				.isEqualTo(TestSaml2JsonPayloads.RELYINGPARTY_REGISTRATION_ID);
		assertThat(authRequest.getId()).isEqualTo(TestSaml2JsonPayloads.ID);
	}

	@Test
	void shouldDeserializeWithNoRegistrationId() throws Exception {
		String json = TestSaml2JsonPayloads.DEFAULT_POST_AUTH_REQUEST_JSON.replace(
				"\"relyingPartyRegistrationId\": \"" + TestSaml2JsonPayloads.RELYINGPARTY_REGISTRATION_ID + "\",", "");

		Saml2PostAuthenticationRequest authRequest = this.mapper.readValue(json, Saml2PostAuthenticationRequest.class);

		assertThat(authRequest).isNotNull();
		assertThat(authRequest.getSamlRequest()).isEqualTo(TestSaml2JsonPayloads.SAML_REQUEST);
		assertThat(authRequest.getRelayState()).isEqualTo(TestSaml2JsonPayloads.RELAY_STATE);
		assertThat(authRequest.getAuthenticationRequestUri())
				.isEqualTo(TestSaml2JsonPayloads.AUTHENTICATION_REQUEST_URI);
		assertThat(authRequest.getRelyingPartyRegistrationId()).isNull();
		assertThat(authRequest.getId()).isEqualTo(TestSaml2JsonPayloads.ID);
	}

	@Test
	void shouldDeserializeWithNoId() throws Exception {
		String json = TestSaml2JsonPayloads.DEFAULT_POST_AUTH_REQUEST_JSON
				.replace(", \"id\": \"" + TestSaml2JsonPayloads.ID + "\"", "");

		Saml2PostAuthenticationRequest authRequest = this.mapper.readValue(json, Saml2PostAuthenticationRequest.class);

		assertThat(authRequest).isNotNull();
		assertThat(authRequest.getSamlRequest()).isEqualTo(TestSaml2JsonPayloads.SAML_REQUEST);
		assertThat(authRequest.getRelayState()).isEqualTo(TestSaml2JsonPayloads.RELAY_STATE);
		assertThat(authRequest.getAuthenticationRequestUri())
				.isEqualTo(TestSaml2JsonPayloads.AUTHENTICATION_REQUEST_URI);
		assertThat(authRequest.getRelyingPartyRegistrationId())
				.isEqualTo(TestSaml2JsonPayloads.RELYINGPARTY_REGISTRATION_ID);
		assertThat(authRequest.getId()).isNull();
	}

}
