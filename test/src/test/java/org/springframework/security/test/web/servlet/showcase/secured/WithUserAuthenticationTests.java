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

package org.springframework.security.test.web.servlet.showcase.secured;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = WithUserAuthenticationTests.Config.class)
@WebAppConfiguration
public class WithUserAuthenticationTests {

	@Autowired
	private WebApplicationContext context;

	private MockMvc mvc;

	@BeforeEach
	public void setup() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.context)
			.apply(SecurityMockMvcConfigurers.springSecurity())
			.build();
	}

	@Test
	@WithMockUser
	public void requestProtectedUrlWithUser() throws Exception {
		this.mvc.perform(get("/"))
			// Ensure we got past Security
			.andExpect(status().isNotFound())
			// Ensure it appears we are authenticated with user
			.andExpect(authenticated().withUsername("user"));
	}

	@Test
	@WithAdminRob
	public void requestProtectedUrlWithAdminRob() throws Exception {
		this.mvc.perform(get("/"))
			// Ensure we got past Security
			.andExpect(status().isNotFound())
			// Ensure it appears we are authenticated with user
			.andExpect(authenticated().withUsername("rob").withRoles("ADMIN"));
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	public void requestProtectedUrlWithAdmin() throws Exception {
		this.mvc.perform(get("/admin"))
			// Ensure we got past Security
			.andExpect(status().isNotFound())
			// Ensure it appears we are authenticated with user
			.andExpect(authenticated().withUsername("user").withRoles("ADMIN"));
	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class Config {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.requestMatchers("/admin/**").hasRole("ADMIN")
					.anyRequest().authenticated())
				.formLogin(withDefaults());
			return http.build();
			// @formatter:on
		}

		@Autowired
		void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER");
			// @formatter:on
		}

	}

}
