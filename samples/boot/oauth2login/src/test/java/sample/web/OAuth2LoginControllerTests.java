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
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.oauth2.core.oidc.IdTokenClaimNames.SUB;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;

/**
 * Tests for {@link OAuth2LoginController}
 *
 * @author Josh Cummings
 */
@RunWith(SpringRunner.class)
@WebMvcTest
@Import({OAuth2LoginController.class, OAuth2LoginControllerTests.OAuth2ClientConfig.class})
public class OAuth2LoginControllerTests {

	static ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("test")
			.authorizationGrantType(AuthorizationGrantType.PASSWORD)
			.clientId("my-client-id")
			.clientName("my-client-name")
			.tokenUri("https://token-uri.example.org")
			.build();

	@Autowired
	MockMvc mvc;

	@Test
	public void rootWhenAuthenticatedReturnsUserAndClient() throws Exception {
		this.mvc.perform(get("/").with(oidcLogin()))
			.andExpect(model().attribute("userName", "test-subject"))
			.andExpect(model().attribute("clientName", "test"))
			.andExpect(model().attribute("userAttributes", Collections.singletonMap(SUB, "test-subject")));
	}

	@Test
	public void rootWhenOverridingClientRegistrationReturnsAccordingly() throws Exception {
		this.mvc.perform(get("/").with(oidcLogin()
				.clientRegistration(clientRegistration)
				.idToken(i -> i.subject("spring-security"))))
				.andExpect(model().attribute("userName", "spring-security"))
				.andExpect(model().attribute("clientName", "my-client-name"))
				.andExpect(model().attribute("userAttributes", Collections.singletonMap(SUB, "spring-security")));
	}

	@Configuration
	static class OAuth2ClientConfig {

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return new InMemoryClientRegistrationRepository(clientRegistration);
		}

		@Bean
		OAuth2AuthorizedClientRepository authorizedClientRepository() {
			return new HttpSessionOAuth2AuthorizedClientRepository();
		}
	}
}
