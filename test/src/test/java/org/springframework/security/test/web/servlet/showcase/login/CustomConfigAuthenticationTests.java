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

package org.springframework.security.test.web.servlet.showcase.login;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = CustomConfigAuthenticationTests.Config.class)
@WebAppConfiguration
public class CustomConfigAuthenticationTests {

	@Autowired
	private WebApplicationContext context;

	@Autowired
	private SecurityContextRepository securityContextRepository;

	private MockMvc mvc;

	@BeforeEach
	public void setup() {
		this.mvc = MockMvcBuilders.webAppContextSetup(this.context).apply(springSecurity()).build();
	}

	@Test
	public void authenticationSuccess() throws Exception {
		this.mvc.perform(formLogin("/authenticate").user("user", "user").password("pass", "password"))
			.andExpect(status().isFound())
			.andExpect(redirectedUrl("/"))
			.andExpect(authenticated().withUsername("user"));
	}

	@Test
	public void withUserSuccess() throws Exception {
		this.mvc.perform(get("/").with(user("user")))
			.andExpect(status().isNotFound())
			.andExpect(authenticated().withUsername("user"));
	}

	@Test
	public void authenticationFailed() throws Exception {
		this.mvc.perform(formLogin("/authenticate").user("user", "notfound").password("pass", "invalid"))
			.andExpect(status().isFound())
			.andExpect(redirectedUrl("/authenticate?error"))
			.andExpect(unauthenticated());
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
					.anyRequest().authenticated())
				.securityContext((context) -> context
					.securityContextRepository(securityContextRepository()))
				.formLogin((login) -> login
					.usernameParameter("user")
					.passwordParameter("pass")
					.loginPage("/authenticate"));
			return http.build();
			// @formatter:on
		}

		// @formatter:off
		@Bean
		UserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder().username("user").password("password").roles("USER").build();
			return new InMemoryUserDetailsManager(user);
		}
		// @formatter:on
		@Bean
		SecurityContextRepository securityContextRepository() {
			HttpSessionSecurityContextRepository repo = new HttpSessionSecurityContextRepository();
			repo.setSpringSecurityContextKey("CUSTOM");
			return repo;
		}

	}

}
