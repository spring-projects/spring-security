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

package org.springframework.security.config.annotation.authorization;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationManagerFactories;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link EnableMultiFactorAuthentication} with
 * {@link Customizer}&lt;{@link AuthorizationManagerFactories.AdditionalRequiredFactorsBuilder}&gt;.
 */
@ExtendWith(SpringExtension.class)
@WebAppConfiguration
@ContextConfiguration(classes = EnableMultiFactorAuthenticationCustomizerTests.ConfigWithCustomizer.class)
class EnableMultiFactorAuthenticationCustomizerTests {

	@Autowired
	MockMvc mvc;

	@Test
	@WithMockUser(username = "user", authorities = "ROLE_USER")
	void whenCustomizerAppliedThenConditionalMfaUsed() throws Exception {
		this.mvc.perform(get("/")).andExpect(status().isOk());
	}

	@Test
	@WithMockUser(username = "admin", authorities = "ROLE_USER")
	void whenCustomizerAppliedAndConditionTrueThenMfaRequired() throws Exception {
		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
	}

	@Test
	@WithMockUser(username = "admin", authorities = { "ROLE_USER", FactorGrantedAuthority.PASSWORD_AUTHORITY,
			FactorGrantedAuthority.OTT_AUTHORITY })
	void whenCustomizerAppliedAndConditionTrueWithMfaThenAuthorized() throws Exception {
		this.mvc.perform(get("/")).andExpect(status().isOk());
	}

	@EnableWebSecurity
	@Configuration
	@EnableMultiFactorAuthentication(
			authorities = { FactorGrantedAuthority.OTT_AUTHORITY, FactorGrantedAuthority.PASSWORD_AUTHORITY })
	static class ConfigWithCustomizer {

		@Bean
		Customizer<AuthorizationManagerFactories.AdditionalRequiredFactorsBuilder<Object>> additionalRequiredFactorsCustomizer() {
			return (builder) -> builder.when((auth) -> "admin".equals(auth.getName()));
		}

		@Bean
		MockMvc mvc(WebApplicationContext context) {
			return MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
		}

		@Bean
		@SuppressWarnings("deprecation")
		UserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.roles("USER")
				.build();
			UserDetails admin = User.withDefaultPasswordEncoder()
				.username("admin")
				.password("password")
				.roles("USER")
				.build();
			return new InMemoryUserDetailsManager(user, admin);
		}

		@RestController
		static class OkController {

			@GetMapping("/")
			String ok() {
				return "ok";
			}

		}

	}

}
