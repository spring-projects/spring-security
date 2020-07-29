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

package org.springframework.security.config.annotation.web.configurers;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
public class PermitAllSupportTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mvc;

	@Test
	public void performWhenUsingPermitAllExactUrlRequestMatcherThenMatchesExactUrl() throws Exception {
		this.spring.register(PermitAllConfig.class).autowire();

		this.mvc.perform(get("/app/xyz").contextPath("/app")).andExpect(status().isNotFound());
		this.mvc.perform(get("/app/xyz?def").contextPath("/app")).andExpect(status().isFound());
		this.mvc.perform(post("/app/abc?def").with(csrf()).contextPath("/app")).andExpect(status().isNotFound());
		this.mvc.perform(get("/app/abc").with(csrf()).contextPath("/app")).andExpect(status().isFound());
	}

	@Test
	public void configureWhenNotAuthorizeRequestsThenException() {
		assertThatCode(() -> this.spring.register(NoAuthorizedUrlsConfig.class).autowire())
				.isInstanceOf(BeanCreationException.class)
				.hasMessageContaining("permitAll only works with HttpSecurity.authorizeRequests");
	}

	@EnableWebSecurity
	static class PermitAllConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.formLogin()
					.loginPage("/xyz").permitAll()
					.loginProcessingUrl("/abc?def").permitAll();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class NoAuthorizedUrlsConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.permitAll();
			// @formatter:on
		}

	}

}
