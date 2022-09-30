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

package org.springframework.security.config.annotation.web.configurers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension.class)
public class SessionManagementConfigurerSessionCreationPolicyTests {

	@Autowired
	MockMvc mvc;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	public void getWhenSharedObjectSessionCreationPolicyConfigurationThenOverrides() throws Exception {
		this.spring.register(StatelessCreateSessionSharedObjectConfig.class).autowire();
		MvcResult result = this.mvc.perform(get("/")).andReturn();
		assertThat(result.getRequest().getSession(false)).isNull();
	}

	@Test
	public void getWhenUserSessionCreationPolicyConfigurationThenOverrides() throws Exception {
		this.spring.register(StatelessCreateSessionUserConfig.class).autowire();
		MvcResult result = this.mvc.perform(get("/")).andReturn();
		assertThat(result.getRequest().getSession(false)).isNull();
	}

	@Test
	public void getWhenDefaultsThenLoginChallengeCreatesSession() throws Exception {
		this.spring.register(DefaultConfig.class, BasicController.class).autowire();
		// @formatter:off
		MvcResult result = this.mvc.perform(get("/"))
				.andExpect(status().isUnauthorized())
				.andReturn();
		// @formatter:on
		assertThat(result.getRequest().getSession(false)).isNotNull();
	}

	@Configuration
	@EnableWebSecurity
	static class StatelessCreateSessionSharedObjectConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			http.setSharedObject(SessionCreationPolicy.class, SessionCreationPolicy.STATELESS);
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class StatelessCreateSessionUserConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			// @formatter:on
			http.setSharedObject(SessionCreationPolicy.class, SessionCreationPolicy.ALWAYS);
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DefaultConfig {

	}

	@RestController
	static class BasicController {

		@GetMapping("/")
		String root() {
			return "ok";
		}

	}

}
