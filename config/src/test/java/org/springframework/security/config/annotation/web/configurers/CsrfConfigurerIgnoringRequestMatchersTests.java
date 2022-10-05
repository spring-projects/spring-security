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
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension.class)
public class CsrfConfigurerIgnoringRequestMatchersTests {

	@Autowired
	MockMvc mvc;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	public void requestWhenIgnoringRequestMatchersThenAugmentedByConfiguredRequestMatcher() throws Exception {
		this.spring.register(IgnoringRequestMatchers.class, BasicController.class).autowire();
		this.mvc.perform(get("/path")).andExpect(status().isForbidden());
		this.mvc.perform(post("/path")).andExpect(status().isOk());
	}

	@Test
	public void requestWhenIgnoringRequestMatchersInLambdaThenAugmentedByConfiguredRequestMatcher() throws Exception {
		this.spring.register(IgnoringRequestInLambdaMatchers.class, BasicController.class).autowire();
		this.mvc.perform(get("/path")).andExpect(status().isForbidden());
		this.mvc.perform(post("/path")).andExpect(status().isOk());
	}

	@Test
	public void requestWhenIgnoringRequestMatcherThenUnionsWithConfiguredIgnoringAntMatchers() throws Exception {
		this.spring.register(IgnoringPathsAndMatchers.class, BasicController.class).autowire();
		this.mvc.perform(put("/csrf")).andExpect(status().isForbidden());
		this.mvc.perform(post("/csrf")).andExpect(status().isOk());
		this.mvc.perform(put("/no-csrf")).andExpect(status().isOk());
	}

	@Test
	public void requestWhenIgnoringRequestMatcherInLambdaThenUnionsWithConfiguredIgnoringAntMatchers()
			throws Exception {
		this.spring.register(IgnoringPathsAndMatchersInLambdaConfig.class, BasicController.class).autowire();
		this.mvc.perform(put("/csrf")).andExpect(status().isForbidden());
		this.mvc.perform(post("/csrf")).andExpect(status().isOk());
		this.mvc.perform(put("/no-csrf")).andExpect(status().isOk());
	}

	@Test
	public void requestWhenIgnoringRequestMatcherPatternThenIgnores() throws Exception {
		this.spring.register(IgnoringPathsAndMatchersPatternConfig.class, BasicController.class).autowire();
		this.mvc.perform(put("/csrf")).andExpect(status().isForbidden());
		this.mvc.perform(post("/csrf")).andExpect(status().isForbidden());
		this.mvc.perform(put("/no-csrf")).andExpect(status().isOk());
	}

	@Test
	public void requestWhenIgnoringRequestMatcherPatternInLambdaThenIgnores() throws Exception {
		this.spring.register(IgnoringPathsAndMatchersPatternInLambdaConfig.class, BasicController.class).autowire();
		this.mvc.perform(put("/csrf")).andExpect(status().isForbidden());
		this.mvc.perform(post("/csrf")).andExpect(status().isForbidden());
		this.mvc.perform(put("/no-csrf")).andExpect(status().isOk());
	}

	@Configuration
	@EnableWebSecurity
	static class IgnoringRequestMatchers {

		RequestMatcher requestMatcher = (request) -> HttpMethod.POST.name().equals(request.getMethod());

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf()
					.requireCsrfProtectionMatcher(new AntPathRequestMatcher("/path"))
					.ignoringRequestMatchers(this.requestMatcher);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class IgnoringRequestInLambdaMatchers {

		RequestMatcher requestMatcher = (request) -> HttpMethod.POST.name().equals(request.getMethod());

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf((csrf) ->
					csrf
						.requireCsrfProtectionMatcher(new AntPathRequestMatcher("/path"))
						.ignoringRequestMatchers(this.requestMatcher)
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class IgnoringPathsAndMatchers {

		RequestMatcher requestMatcher = (request) -> HttpMethod.POST.name().equals(request.getMethod());

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf()
					.ignoringRequestMatchers(new AntPathRequestMatcher("/no-csrf"))
					.ignoringRequestMatchers(this.requestMatcher);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class IgnoringPathsAndMatchersInLambdaConfig {

		RequestMatcher requestMatcher = (request) -> HttpMethod.POST.name().equals(request.getMethod());

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf((csrf) ->
					csrf
						.ignoringRequestMatchers(new AntPathRequestMatcher("/no-csrf"))
						.ignoringRequestMatchers(this.requestMatcher)
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class IgnoringPathsAndMatchersPatternConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf()
					.ignoringRequestMatchers("/no-csrf");
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class IgnoringPathsAndMatchersPatternInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf((csrf) -> csrf
					.ignoringRequestMatchers("/no-csrf")
				);
			// @formatter:on
			return http.build();
		}

	}

	@RestController
	public static class BasicController {

		@RequestMapping("/path")
		public String path() {
			return "path";
		}

		@RequestMapping("/csrf")
		public String csrf() {
			return "csrf";
		}

		@RequestMapping("/no-csrf")
		public String noCsrf() {
			return "no-csrf";
		}

	}

}
