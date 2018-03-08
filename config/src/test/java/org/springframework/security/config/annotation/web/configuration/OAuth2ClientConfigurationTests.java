/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.configuration;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.OAuth2Client;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link OAuth2ClientConfiguration}.
 *
 * @author Joe Grandja
 */
public class OAuth2ClientConfigurationTests {
	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void requestWhenAuthorizedClientFoundThenOAuth2ClientArgumentsResolved() throws Exception {
		String clientRegistrationId = "client1";
		String principalName = "user1";

		ClientRegistrationRepository clientRegistrationRepository = mock(ClientRegistrationRepository.class);
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(clientRegistrationId)
				.clientId("client-id")
				.clientSecret("secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.redirectUriTemplate("{baseUrl}/client1")
				.scope("scope1", "scope2")
				.authorizationUri("https://provider.com/oauth2/auth")
				.tokenUri("https://provider.com/oauth2/token")
				.clientName("Client 1")
				.build();
		when(clientRegistrationRepository.findByRegistrationId(clientRegistrationId)).thenReturn(clientRegistration);

		OAuth2AuthorizedClientService authorizedClientService = mock(OAuth2AuthorizedClientService.class);
		OAuth2AuthorizedClient authorizedClient = mock(OAuth2AuthorizedClient.class);
		when(authorizedClientService.loadAuthorizedClient(clientRegistrationId, principalName)).thenReturn(authorizedClient);

		OAuth2AccessToken accessToken = mock(OAuth2AccessToken.class);
		when(authorizedClient.getAccessToken()).thenReturn(accessToken);

		OAuth2ClientArgumentResolverConfig.CLIENT_REGISTRATION_REPOSITORY = clientRegistrationRepository;
		OAuth2ClientArgumentResolverConfig.AUTHORIZED_CLIENT_SERVICE = authorizedClientService;
		this.spring.register(OAuth2ClientArgumentResolverConfig.class).autowire();

		this.mockMvc.perform(get("/access-token").with(user(principalName)))
			.andExpect(status().isOk())
			.andExpect(content().string("resolved"));
		this.mockMvc.perform(get("/authorized-client").with(user(principalName)))
			.andExpect(status().isOk())
			.andExpect(content().string("resolved"));
		this.mockMvc.perform(get("/client-registration").with(user(principalName)))
			.andExpect(status().isOk())
			.andExpect(content().string("resolved"));
	}

	@EnableWebMvc
	@EnableWebSecurity
	static class OAuth2ClientArgumentResolverConfig extends WebSecurityConfigurerAdapter {
		static ClientRegistrationRepository CLIENT_REGISTRATION_REPOSITORY;
		static OAuth2AuthorizedClientService AUTHORIZED_CLIENT_SERVICE;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
		}

		@RestController
		public class Controller {

			@GetMapping("/access-token")
			public String accessToken(@OAuth2Client("client1") OAuth2AccessToken accessToken) {
				return accessToken != null ? "resolved" : "not-resolved";
			}

			@GetMapping("/authorized-client")
			public String authorizedClient(@OAuth2Client("client1") OAuth2AuthorizedClient authorizedClient) {
				return authorizedClient != null ? "resolved" : "not-resolved";
			}

			@GetMapping("/client-registration")
			public String clientRegistration(@OAuth2Client("client1") ClientRegistration clientRegistration) {
				return clientRegistration != null ? "resolved" : "not-resolved";
			}
		}

		@Bean
		public ClientRegistrationRepository clientRegistrationRepository() {
			return CLIENT_REGISTRATION_REPOSITORY;
		}

		@Bean
		public OAuth2AuthorizedClientService authorizedClientService() {
			return AUTHORIZED_CLIENT_SERVICE;
		}
	}
}
