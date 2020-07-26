/*
 * Copyright 2002-2018 the original author or authors.
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

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.test.SpringTestRule;
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
public class SessionManagementConfigurerSessionCreationPolicyTests {

	@Autowired
	MockMvc mvc;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

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

		MvcResult result = this.mvc.perform(get("/")).andExpect(status().isUnauthorized()).andReturn();

		assertThat(result.getRequest().getSession(false)).isNotNull();
	}

	@EnableWebSecurity
	static class StatelessCreateSessionSharedObjectConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			super.configure(http);
			http.setSharedObject(SessionCreationPolicy.class, SessionCreationPolicy.STATELESS);
		}

	}

	@EnableWebSecurity
	static class StatelessCreateSessionUserConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			super.configure(http);
			// @formatter:off
			http
					.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			// @formatter:on

			http.setSharedObject(SessionCreationPolicy.class, SessionCreationPolicy.ALWAYS);
		}

	}

	@EnableWebSecurity
	static class DefaultConfig extends WebSecurityConfigurerAdapter {

	}

	@RestController
	static class BasicController {

		@GetMapping("/")
		public String root() {
			return "ok";
		}

	}

}
