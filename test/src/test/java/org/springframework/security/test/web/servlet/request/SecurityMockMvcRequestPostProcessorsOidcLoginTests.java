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

package org.springframework.security.test.web.servlet.request;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.TestOidcIdTokens;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.mockito.Mockito.mock;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link SecurityMockMvcRequestPostProcessors#oidcLogin()}
 *
 * @author Josh Cummings
 * @since 5.3
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration
@WebAppConfiguration
public class SecurityMockMvcRequestPostProcessorsOidcLoginTests {

	@Autowired
	WebApplicationContext context;

	MockMvc mvc;

	@BeforeEach
	public void setup() {
		// @formatter:off
		this.mvc = MockMvcBuilders
			.webAppContextSetup(this.context)
			.apply(springSecurity())
			.build();
		// @formatter:on
	}

	@AfterEach
	public void cleanup() {
		TestSecurityContextHolder.clearContext();
	}

	@Test
	public void oidcLoginWhenUsingDefaultsThenProducesDefaultAuthentication() throws Exception {
		this.mvc.perform(get("/name").with(oidcLogin())).andExpect(content().string("user"));
		this.mvc.perform(get("/admin/id-token/name").with(oidcLogin())).andExpect(status().isForbidden());
	}

	@Test
	public void oidcLoginWhenUsingDefaultsThenProducesDefaultAuthorizedClient() throws Exception {
		this.mvc.perform(get("/access-token").with(oidcLogin())).andExpect(content().string("access-token"));
	}

	@Test
	public void oidcLoginWhenAuthoritiesSpecifiedThenGrantsAccess() throws Exception {
		this.mvc.perform(get("/admin/scopes").with(oidcLogin().authorities(new SimpleGrantedAuthority("SCOPE_admin"))))
				.andExpect(content().string("[\"SCOPE_admin\"]"));
	}

	@Test
	public void oidcLoginWhenIdTokenSpecifiedThenUserHasClaims() throws Exception {
		this.mvc.perform(get("/id-token/iss").with(oidcLogin().idToken((i) -> i.issuer("https://idp.example.org"))))
				.andExpect(content().string("https://idp.example.org"));
	}

	@Test
	public void oidcLoginWhenUserInfoSpecifiedThenUserHasClaims() throws Exception {
		this.mvc.perform(get("/user-info/email").with(oidcLogin().userInfoToken((u) -> u.email("email@email"))))
				.andExpect(content().string("email@email"));
	}

	@Test
	public void oidcLoginWhenNameSpecifiedThenUserHasName() throws Exception {
		OidcUser oidcUser = new DefaultOidcUser(AuthorityUtils.commaSeparatedStringToAuthorityList("SCOPE_read"),
				OidcIdToken.withTokenValue("id-token").claim("custom-attribute", "test-subject").build(),
				"custom-attribute");
		this.mvc.perform(get("/id-token/custom-attribute").with(oidcLogin().oidcUser(oidcUser)))
				.andExpect(content().string("test-subject"));
		this.mvc.perform(get("/name").with(oidcLogin().oidcUser(oidcUser))).andExpect(content().string("test-subject"));
		this.mvc.perform(get("/client-name").with(oidcLogin().oidcUser(oidcUser)))
				.andExpect(content().string("test-subject"));
	}

	// gh-7794
	@Test
	public void oidcLoginWhenOidcUserSpecifiedThenLastCalledTakesPrecedence() throws Exception {
		OidcUser oidcUser = new DefaultOidcUser(AuthorityUtils.createAuthorityList("SCOPE_read"),
				TestOidcIdTokens.idToken().build());
		this.mvc.perform(get("/id-token/sub").with(oidcLogin().idToken((i) -> i.subject("foo")).oidcUser(oidcUser)))
				.andExpect(status().isOk()).andExpect(content().string("subject"));
		this.mvc.perform(get("/id-token/sub").with(oidcLogin().oidcUser(oidcUser).idToken((i) -> i.subject("bar"))))
				.andExpect(content().string("bar"));
	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class OAuth2LoginConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.requestMatchers("/admin/**").hasAuthority("SCOPE_admin")
					.anyRequest().hasAuthority("SCOPE_read")
					.and()
				.oauth2Login();
			return http.build();
			// @formatter:on
		}

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return mock(ClientRegistrationRepository.class);
		}

		@Bean
		OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository() {
			return mock(OAuth2AuthorizedClientRepository.class);
		}

		@RestController
		static class PrincipalController {

			@GetMapping("/name")
			String name(@AuthenticationPrincipal OidcUser oidcUser) {
				return oidcUser.getName();
			}

			@GetMapping("/client-name")
			String clientName(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
				return authorizedClient.getPrincipalName();
			}

			@GetMapping("/access-token")
			String authorizedClient(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
				return authorizedClient.getAccessToken().getTokenValue();
			}

			@GetMapping("/id-token/{claim}")
			String idTokenClaim(@AuthenticationPrincipal OidcUser oidcUser, @PathVariable("claim") String claim) {
				return oidcUser.getIdToken().getClaim(claim);
			}

			@GetMapping("/user-info/{claim}")
			String userInfoClaim(@AuthenticationPrincipal OidcUser oidcUser, @PathVariable("claim") String claim) {
				return oidcUser.getUserInfo().getClaim(claim);
			}

			@GetMapping("/admin/scopes")
			List<String> scopes(
					@AuthenticationPrincipal(expression = "authorities") Collection<GrantedAuthority> authorities) {
				return authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
			}

		}

	}

}
