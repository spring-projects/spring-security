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
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link HttpSecurity.RequestMatcherConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension.class)
public class RequestMatcherConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	// SEC-2908
	@Test
	public void authorizeRequestsWhenInvokedMultipleTimesThenChainsPaths() throws Exception {
		this.spring.register(Sec2908Config.class).autowire();
		// @formatter:off
		this.mvc.perform(get("/oauth/abc"))
				.andExpect(status().isForbidden());
		this.mvc.perform(get("/api/abc"))
				.andExpect(status().isForbidden());
		// @formatter:on
	}

	@Test
	public void authorizeRequestsWhenInvokedMultipleTimesInLambdaThenChainsPaths() throws Exception {
		this.spring.register(AuthorizeRequestInLambdaConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(get("/oauth/abc"))
				.andExpect(status().isForbidden());
		this.mvc.perform(get("/api/abc"))
				.andExpect(status().isForbidden());
		// @formatter:on
	}

	@Configuration
	@EnableWebSecurity
	static class Sec2908Config {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.securityMatchers()
					.requestMatchers(new AntPathRequestMatcher("/api/**"))
					.and()
				.securityMatchers()
					.requestMatchers(new AntPathRequestMatcher("/oauth/**"))
					.and()
				.authorizeRequests()
					.anyRequest().denyAll();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AuthorizeRequestInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.securityMatchers((matchers) ->
					matchers
						.requestMatchers(new AntPathRequestMatcher("/api/**"))
				)
				.securityMatchers((matchers) ->
					matchers
						.requestMatchers(new AntPathRequestMatcher("/oauth/**"))
				)
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().denyAll()
				);
			return http.build();
			// @formatter:on
		}

	}

}
