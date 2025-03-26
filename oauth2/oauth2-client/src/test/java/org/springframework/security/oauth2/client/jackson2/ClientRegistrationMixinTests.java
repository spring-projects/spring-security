/*
 * Copyright 2002-2025 the original author or authors.
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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

public class ClientRegistrationMixinTests {

	private ObjectMapper mapper;

	@BeforeEach
	void setUp() {
		ClassLoader loader = getClass().getClassLoader();
		this.mapper = new ObjectMapper();
		this.mapper.registerModules(SecurityJackson2Modules.getModules(loader));
	}

	@ParameterizedTest
	@MethodSource("deserializeWhenMixinRegisteredThenDeserializes")
	void deserializeWhenMixinRegisteredThenDeserializes(
			ClientRegistration expectedClientRegistration
	) throws Exception {
		String json = asJson(expectedClientRegistration);
		ClientRegistration clientRegistration = this.mapper.readValue(json, ClientRegistration.class);
		assertThat(clientRegistration.getClientAuthenticationMethod()).isEqualTo(expectedClientRegistration.getClientAuthenticationMethod());
	}

	private String asJson(ClientRegistration expectedClientRegistration) {
		// @formatter:off
		return "{" +
				"  \"@class\":\"org.springframework.security.oauth2.client.registration.ClientRegistration\"," +
				"  \"registrationId\":\"registration-id\"," +
				"  \"clientId\":\"client-id\"," +
				"  \"clientSecret\":\"client-secret\"," +
				"  \"clientAuthenticationMethod\":{" +
				"    \"value\":\"" + expectedClientRegistration.getClientAuthenticationMethod().getValue() + "\"" +
				"  }," +
				"  \"authorizationGrantType\":{" +
				"    \"value\":\"" + expectedClientRegistration.getAuthorizationGrantType().getValue() + "\"" +
				"  }," +
				"  \"redirectUri\":\"{baseUrl}/{action}/oauth2/code/{registrationId}\"," +
				"  \"scopes\":[" +
				"    \"java.util.Collections$UnmodifiableSet\",[\"read:user\"]" +
				"  ]," +
				"  \"providerDetails\":{" +
				"    \"@class\":\"org.springframework.security.oauth2.client.registration.ClientRegistration$ProviderDetails\"," +
				"    \"authorizationUri\":\"https://example.com/login/oauth/authorize\"," +
				"    \"tokenUri\": \"https://example.com/login/oauth/access_token\"," +
				"    \"userInfoEndpoint\":{" +
				"      \"@class\":\"org.springframework.security.oauth2.client.registration.ClientRegistration$ProviderDetails$UserInfoEndpoint\"," +
				"      \"uri\":\"https://api.example.com/user\"," +
				"      \"authenticationMethod\":{" +
				"        \"value\":\"header\"" +
				"      }," +
				"      \"userNameAttributeName\":\"id\"" +
				"    }," +
				"    \"jwkSetUri\":\"https://example.com/oauth2/jwk\"," +
				"    \"issuerUri\":\"https://example.com\"," +
				"    \"configurationMetadata\":{" +
				"      \"@class\":\"java.util.Collections$UnmodifiableMap\"" +
				"    }" +
				"  }," +
				"  \"clientName\":\"Client Name\"}";
		// @formatter:on
	}

	static Stream<Arguments> deserializeWhenMixinRegisteredThenDeserializes() {
		return Stream.of(
				Arguments.of(
						TestClientRegistrations.clientRegistration()
								.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
								.build()
				),
				Arguments.of(
						TestClientRegistrations.clientRegistration()
								.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
								.build()
				),
				Arguments.of(
						TestClientRegistrations.clientRegistration()
								.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
								.build()
				)
		);
	}
}
