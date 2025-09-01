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

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings("removal")
class Saml2LogoutRequestMixinTests {

	private JsonMapper mapper;

	@BeforeEach
	void setUp() {
		ClassLoader loader = getClass().getClassLoader();
		this.mapper = JsonMapper.builder().addModules(SecurityJacksonModules.getModules(loader)).build();
	}

	@Test
	void shouldSerialize() throws Exception {
		Saml2LogoutRequest request = TestSaml2JsonPayloads.createDefaultSaml2LogoutRequest();

		String requestJson = this.mapper.writeValueAsString(request);

		JSONAssert.assertEquals(TestSaml2JsonPayloads.DEFAULT_LOGOUT_REQUEST_JSON, requestJson, true);
	}

	@Test
	void shouldDeserialize() {
		deserializeAndAssertRequest();
	}

	// gh-12539
	@Test
	void shouldDeserializeWhenFailOnMissingCreatorPropertiesEnabled() {
		// Jackson will use reflection to initialize the binding property if this is not
		// enabled
		JsonMapper customizedMapper = this.mapper.rebuild()
			.enable(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES)
			.build();
		deserializeAndAssertRequest();
	}

	private void deserializeAndAssertRequest() throws JacksonException {
		Saml2LogoutRequest logoutRequest = this.mapper.readValue(TestSaml2JsonPayloads.DEFAULT_LOGOUT_REQUEST_JSON,
				Saml2LogoutRequest.class);

		assertThat(logoutRequest).isNotNull();
		assertThat(logoutRequest.getId()).isEqualTo(TestSaml2JsonPayloads.ID);
		assertThat(logoutRequest.getRelyingPartyRegistrationId())
			.isEqualTo(TestSaml2JsonPayloads.RELYINGPARTY_REGISTRATION_ID);
		assertThat(logoutRequest.getSamlRequest()).isEqualTo(TestSaml2JsonPayloads.SAML_REQUEST);
		assertThat(logoutRequest.getRelayState()).isEqualTo(TestSaml2JsonPayloads.RELAY_STATE);
		assertThat(logoutRequest.getLocation()).isEqualTo(TestSaml2JsonPayloads.LOCATION);
		assertThat(logoutRequest.getBinding()).isEqualTo(Saml2MessageBinding.REDIRECT);
		Map<String, String> expectedParams = new HashMap<>();
		expectedParams.put("SAMLRequest", TestSaml2JsonPayloads.SAML_REQUEST);
		expectedParams.put("RelayState", TestSaml2JsonPayloads.RELAY_STATE);
		expectedParams.put("AdditionalParam", TestSaml2JsonPayloads.ADDITIONAL_PARAM);
		assertThat(logoutRequest.getParameters()).containsAllEntriesOf(expectedParams);
	}

}
