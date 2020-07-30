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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link HttpSecurity.RequestMatcherConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 */
public class RequestMatcherConfigurerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	// SEC-2908
	@Test
	public void authorizeRequestsWhenInvokedMultipleTimesThenChainsPaths() throws Exception {
		this.spring.register(Sec2908Config.class).autowire();

		this.mvc.perform(get("/oauth/abc")).andExpect(status().isForbidden());
		this.mvc.perform(get("/api/abc")).andExpect(status().isForbidden());
	}

	@Test
	public void authorizeRequestsWhenInvokedMultipleTimesInLambdaThenChainsPaths() throws Exception {
		this.spring.register(AuthorizeRequestInLambdaConfig.class).autowire();

		this.mvc.perform(get("/oauth/abc")).andExpect(status().isForbidden());
		this.mvc.perform(get("/api/abc")).andExpect(status().isForbidden());
	}

	@EnableWebSecurity
	static class Sec2908Config extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestMatchers()
					.antMatchers("/api/**")
					.and()
				.requestMatchers()
					.antMatchers("/oauth/**")
					.and()
				.authorizeRequests()
					.anyRequest().denyAll();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class AuthorizeRequestInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestMatchers((requestMatchers) ->
					requestMatchers
						.antMatchers("/api/**")
				)
				.requestMatchers((requestMatchers) ->
					requestMatchers
						.antMatchers("/oauth/**")
				)
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().denyAll()
				);
			// @formatter:on
		}

	}

}
