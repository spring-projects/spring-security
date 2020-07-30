/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.test.web.servlet.request;

import javax.servlet.http.HttpServletRequest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Client;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;

/**
 * Tests for {@link SecurityMockMvcRequestPostProcessors#oidcLogin()}
 *
 * @author Josh Cummings
 * @since 5.3
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class SecurityMockMvcRequestPostProcessorsOAuth2ClientTests {

	@Autowired
	WebApplicationContext context;

	MockMvc mvc;

	@Before
	public void setup() {
		// @formatter:off
		this.mvc = MockMvcBuilders
			.webAppContextSetup(this.context)
			.apply(springSecurity())
			.build();
		// @formatter:on
	}

	@After
	public void cleanup() {
		TestSecurityContextHolder.clearContext();
	}

	@Test
	public void oauth2ClientWhenUsingDefaultsThenException() throws Exception {

		assertThatCode(() -> oauth2Client().postProcessRequest(new MockHttpServletRequest()))
				.isInstanceOf(IllegalArgumentException.class).hasMessageContaining("ClientRegistration");
	}

	@Test
	public void oauth2ClientWhenUsingDefaultsThenProducesDefaultAuthorizedClient() throws Exception {

		this.mvc.perform(get("/access-token").with(oauth2Client("registration-id")))
				.andExpect(content().string("access-token"));
		this.mvc.perform(get("/client-id").with(oauth2Client("registration-id")))
				.andExpect(content().string("test-client"));
	}

	@Test
	public void oauth2ClientWhenClientRegistrationThenUses() throws Exception {

		ClientRegistration clientRegistration = TestClientRegistrations.clientRegistration()
				.registrationId("registration-id").clientId("client-id").build();
		this.mvc.perform(get("/client-id").with(oauth2Client().clientRegistration(clientRegistration)))
				.andExpect(content().string("client-id"));
	}

	@Test
	public void oauth2ClientWhenClientRegistrationConsumerThenUses() throws Exception {

		this.mvc.perform(get("/client-id")
				.with(oauth2Client("registration-id").clientRegistration((c) -> c.clientId("client-id"))))
				.andExpect(content().string("client-id"));
	}

	@Test
	public void oauth2ClientWhenPrincipalNameThenUses() throws Exception {
		this.mvc.perform(get("/principal-name").with(oauth2Client("registration-id").principalName("test-subject")))
				.andExpect(content().string("test-subject"));
	}

	@Test
	public void oauth2ClientWhenAccessTokenThenUses() throws Exception {
		OAuth2AccessToken accessToken = TestOAuth2AccessTokens.noScopes();
		this.mvc.perform(get("/access-token").with(oauth2Client("registration-id").accessToken(accessToken)))
				.andExpect(content().string("no-scopes"));
	}

	@Test
	public void oauth2ClientWhenUsedOnceThenDoesNotAffectRemainingTests() throws Exception {
		this.mvc.perform(get("/client-id").with(oauth2Client("registration-id")))
				.andExpect(content().string("test-client"));

		OAuth2AuthorizedClient client = new OAuth2AuthorizedClient(TestClientRegistrations.clientRegistration().build(),
				"sub", TestOAuth2AccessTokens.noScopes());
		OAuth2AuthorizedClientRepository repository = this.context.getBean(OAuth2AuthorizedClientRepository.class);
		given(repository.loadAuthorizedClient(eq("registration-id"), any(Authentication.class),
				any(HttpServletRequest.class))).willReturn(client);
		this.mvc.perform(get("/client-id")).andExpect(content().string("client-id"));
		verify(repository).loadAuthorizedClient(eq("registration-id"), any(Authentication.class),
				any(HttpServletRequest.class));
	}

	@EnableWebSecurity
	@EnableWebMvc
	static class OAuth2ClientConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authz) -> authz
					.anyRequest().permitAll()
				)
				.oauth2Client();
			// @formatter:on
		}

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return mock(ClientRegistrationRepository.class);
		}

		@Bean
		OAuth2AuthorizedClientRepository authorizedClientRepository() {
			return mock(OAuth2AuthorizedClientRepository.class);
		}

		@RestController
		static class PrincipalController {

			@GetMapping("/access-token")
			String accessToken(
					@RegisteredOAuth2AuthorizedClient("registration-id") OAuth2AuthorizedClient authorizedClient) {
				return authorizedClient.getAccessToken().getTokenValue();
			}

			@GetMapping("/principal-name")
			String principalName(
					@RegisteredOAuth2AuthorizedClient("registration-id") OAuth2AuthorizedClient authorizedClient) {
				return authorizedClient.getPrincipalName();
			}

			@GetMapping("/client-id")
			String clientId(
					@RegisteredOAuth2AuthorizedClient("registration-id") OAuth2AuthorizedClient authorizedClient) {
				return authorizedClient.getClientRegistration().getClientId();
			}

		}

	}

}
