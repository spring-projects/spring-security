/*
 * Copyright 2002-2019 the original author or authors.
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

package sample.web;

import java.util.Collections;

import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Login;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;

/**
 * Tests for {@link OAuth2LoginController}
 *
 * @author Josh Cummings
 */
@RunWith(SpringRunner.class)
@WebMvcTest(OAuth2LoginController.class)
public class OAuth2LoginControllerTests {

	@Autowired
	MockMvc mvc;

	@MockBean
	ClientRegistrationRepository clientRegistrationRepository;

	@TestConfiguration
	static class AuthorizedClient {
		@Bean
		public OAuth2AuthorizedClientRepository authorizedClientRepository() {
			return new HttpSessionOAuth2AuthorizedClientRepository();
		}
	}

	@Test
	public void rootWhenAuthenticatedReturnsUserAndClient() throws Exception {
		this.mvc.perform(get("/").with(oauth2Login()))
			.andExpect(model().attribute("userName", "user"))
			.andExpect(model().attribute("clientName", "test"))
			.andExpect(model().attribute("userAttributes", Collections.singletonMap("sub", "user")));
	}

	@Test
	public void rootWhenOverridingClientRegistrationReturnsAccordingly() throws Exception {
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("test")
				.authorizationGrantType(AuthorizationGrantType.PASSWORD)
				.clientId("my-client-id")
				.clientName("my-client-name")
				.tokenUri("https://token-uri.example.org")
				.build();

		this.mvc.perform(get("/").with(oauth2Login()
				.clientRegistration(clientRegistration)
				.attributes(a -> a.put("sub", "spring-security"))))
				.andExpect(model().attribute("userName", "spring-security"))
				.andExpect(model().attribute("clientName", "my-client-name"))
				.andExpect(model().attribute("userAttributes", Collections.singletonMap("sub", "spring-security")));
	}
}
