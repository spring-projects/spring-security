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
package org.springframework.security.test.web.servlet.request;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.mockito.Mockito.mock;
import static org.springframework.security.oauth2.client.registration.TestClientRegistrations.clientRegistration;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Login;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link SecurityMockMvcRequestPostProcessors#oauth2Login()}
 *
 * @author Josh Cummings
 * @since 5.3
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
@WebAppConfiguration
public class SecurityMockMvcRequestPostProcessorsOAuth2LoginTests {
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

	@Test
	public void oauth2LoginWhenUsingDefaultsThenProducesDefaultAuthentication()
		throws Exception {

		this.mvc.perform(get("/name").with(oauth2Login()))
				.andExpect(content().string("user"));
		this.mvc.perform(get("/admin/id-token/name").with(oauth2Login()))
				.andExpect(status().isForbidden());
	}

	@Test
	public void oauth2LoginWhenUsingDefaultsThenProducesDefaultAuthorizedClient()
			throws Exception {

		this.mvc.perform(get("/client-id").with(oauth2Login()))
				.andExpect(content().string("test-client"));
	}

	@Test
	public void oauth2LoginWhenAuthoritiesSpecifiedThenGrantsAccess() throws Exception {
		this.mvc.perform(get("/admin/scopes")
				.with(oauth2Login().authorities(new SimpleGrantedAuthority("SCOPE_admin"))))
				.andExpect(content().string("[\"SCOPE_admin\"]"));
	}

	@Test
	public void oauth2LoginWhenAttributeSpecifiedThenUserHasAttribute() throws Exception {
		this.mvc.perform(get("/attributes/iss")
				.with(oauth2Login().attributes(a -> a.put("iss", "https://idp.example.org"))))
				.andExpect(content().string("https://idp.example.org"));
	}

	@Test
	public void oauth2LoginWhenNameSpecifiedThenUserHasName() throws Exception {
		OAuth2User oauth2User = new DefaultOAuth2User(
				AuthorityUtils.commaSeparatedStringToAuthorityList("SCOPE_read"),
				Collections.singletonMap("custom-attribute", "test-subject"),
				"custom-attribute");
		this.mvc.perform(get("/attributes/custom-attribute")
				.with(oauth2Login().oauth2User(oauth2User)))
				.andExpect(content().string("test-subject"));

		this.mvc.perform(get("/name")
				.with(oauth2Login().oauth2User(oauth2User)))
				.andExpect(content().string("test-subject"));

		this.mvc.perform(get("/client-name")
				.with(oauth2Login().oauth2User(oauth2User)))
				.andExpect(content().string("test-subject"));
	}

	@Test
	public void oauth2LoginWhenClientRegistrationSpecifiedThenUses() throws Exception {
		this.mvc.perform(get("/client-id")
				.with(oauth2Login().clientRegistration(clientRegistration().build())))
				.andExpect(content().string("client-id"));
	}

	@Test
	public void oauth2LoginWhenOAuth2UserSpecifiedThenLastCalledTakesPrecedence() throws Exception {
		OAuth2User oauth2User = new DefaultOAuth2User(
				AuthorityUtils.createAuthorityList("SCOPE_read"),
				Collections.singletonMap("username", "user"),
				"username");

		this.mvc.perform(get("/attributes/sub")
				.with(oauth2Login()
						.attributes(a -> a.put("sub", "bar"))
						.oauth2User(oauth2User)))
				.andExpect(status().isOk())
				.andExpect(content().string("no-attribute"));
		this.mvc.perform(get("/attributes/sub")
				.with(oauth2Login()
						.oauth2User(oauth2User)
						.attributes(a -> a.put("sub", "bar"))))
				.andExpect(content().string("bar"));
	}

	@EnableWebSecurity
	@EnableWebMvc
	static class OAuth2LoginConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests(authorize -> authorize
					.mvcMatchers("/admin/**").hasAuthority("SCOPE_admin")
					.anyRequest().hasAuthority("SCOPE_read")
				).oauth2Login();
		}

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return mock(ClientRegistrationRepository.class);
		}

		@Bean
		OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository() {
			return new HttpSessionOAuth2AuthorizedClientRepository();
		}

		@RestController
		static class PrincipalController {
			@GetMapping("/name")
			String name(@AuthenticationPrincipal OAuth2User oauth2User) {
				return oauth2User.getName();
			}

			@GetMapping("/client-id")
			String authorizedClient(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
				return authorizedClient.getClientRegistration().getClientId();
			}

			@GetMapping("/client-name")
			String clientName(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
				return authorizedClient.getPrincipalName();
			}

			@GetMapping("/attributes/{attribute}")
			String attributes(
					@AuthenticationPrincipal OAuth2User oauth2User, @PathVariable("attribute") String attribute) {

				return Optional.ofNullable((String) oauth2User.getAttribute(attribute)).orElse("no-attribute");
			}

			@GetMapping("/admin/scopes")
			List<String> scopes(
					@AuthenticationPrincipal(expression = "authorities") Collection<GrantedAuthority> authorities) {

				return authorities.stream().map(GrantedAuthority::getAuthority)
						.collect(Collectors.toList());
			}
		}
	}
}
