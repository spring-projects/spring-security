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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rob Winch
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration
@WebAppConfiguration
public class Sec2935Tests {

	@Autowired
	WebApplicationContext context;

	MockMvc mvc;

	@BeforeEach
	public void setup() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.context).apply(springSecurity()).build();
	}

	// SEC-2935
	@Test
	public void postProcessorUserNoUser() throws Exception {
		this.mvc.perform(get("/admin/abc").with(user("user").roles("ADMIN", "USER"))).andExpect(status().isNotFound())
				.andExpect(authenticated().withUsername("user"));
		this.mvc.perform(get("/admin/abc")).andExpect(status().isUnauthorized()).andExpect(unauthenticated());
	}

	@Test
	public void postProcessorUserOtherUser() throws Exception {
		this.mvc.perform(get("/admin/abc").with(user("user1").roles("ADMIN", "USER"))).andExpect(status().isNotFound())
				.andExpect(authenticated().withUsername("user1"));
		this.mvc.perform(get("/admin/abc").with(user("user2").roles("USER"))).andExpect(status().isForbidden())
				.andExpect(authenticated().withUsername("user2"));
	}

	@WithMockUser
	@Test
	public void postProcessorUserWithMockUser() throws Exception {
		this.mvc.perform(get("/admin/abc").with(user("user1").roles("ADMIN", "USER"))).andExpect(status().isNotFound())
				.andExpect(authenticated().withUsername("user1"));
		this.mvc.perform(get("/admin/abc")).andExpect(status().isForbidden())
				.andExpect(authenticated().withUsername("user"));
	}

	// SEC-2941
	@Test
	public void defaultRequest() throws Exception {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.context).apply(springSecurity())
				.defaultRequest(get("/").with(user("default"))).build();
		this.mvc.perform(get("/admin/abc").with(user("user1").roles("ADMIN", "USER"))).andExpect(status().isNotFound())
				.andExpect(authenticated().withUsername("user1"));
		this.mvc.perform(get("/admin/abc")).andExpect(status().isForbidden())
				.andExpect(authenticated().withUsername("default"));
	}

	@Disabled
	@WithMockUser
	@Test
	public void defaultRequestOverridesWithMockUser() throws Exception {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.context).apply(springSecurity())
				.defaultRequest(get("/").with(user("default"))).build();
		this.mvc.perform(get("/admin/abc").with(user("user1").roles("ADMIN", "USER"))).andExpect(status().isNotFound())
				.andExpect(authenticated().withUsername("user1"));
		this.mvc.perform(get("/admin/abc")).andExpect(status().isForbidden())
				.andExpect(authenticated().withUsername("default"));
	}

	@EnableWebSecurity
	@Configuration
	@EnableWebMvc
	static class Config {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.requestMatchers("/admin/**").hasRole("ADMIN")
					.anyRequest().authenticated()
					.and()
				.httpBasic();
			return http.build();
			// @formatter:on
		}

		@Autowired
		void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication();
		}

	}

}
