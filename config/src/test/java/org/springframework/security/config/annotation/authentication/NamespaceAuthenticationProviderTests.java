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

package org.springframework.security.config.annotation.authentication;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;

/**
 * @author Rob Winch
 */
@ExtendWith(SpringTestContextExtension.class)
public class NamespaceAuthenticationProviderTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Test
	// authentication-provider@ref
	public void authenticationProviderRef() throws Exception {
		this.spring.register(AuthenticationProviderRefConfig.class).autowire();
		this.mockMvc.perform(formLogin()).andExpect(authenticated().withUsername("user"));
	}

	@Test
	// authentication-provider@user-service-ref
	public void authenticationProviderUserServiceRef() throws Exception {
		this.spring.register(AuthenticationProviderRefConfig.class).autowire();
		this.mockMvc.perform(formLogin()).andExpect(authenticated().withUsername("user"));
	}

	@Configuration
	@EnableWebSecurity
	static class AuthenticationProviderRefConfig {

		@Autowired
		void configure(AuthenticationManagerBuilder auth) {
			// @formatter:off
			auth
				.authenticationProvider(authenticationProvider());
			// @formatter:on
		}

		@Bean
		DaoAuthenticationProvider authenticationProvider() {
			return new DaoAuthenticationProvider(new InMemoryUserDetailsManager(PasswordEncodedUser.user()));
		}

	}

	@Configuration
	@EnableWebSecurity
	static class UserServiceRefConfig {

		@Autowired
		void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.userDetailsService(userDetailsService());
			// @formatter:on
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

}
