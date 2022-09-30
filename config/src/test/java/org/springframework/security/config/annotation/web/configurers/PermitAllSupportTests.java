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

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
@ExtendWith(SpringTestContextExtension.class)
public class PermitAllSupportTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mvc;

	@Test
	public void performWhenUsingPermitAllExactUrlRequestMatcherThenMatchesExactUrl() throws Exception {
		this.spring.register(PermitAllConfig.class).autowire();
		MockHttpServletRequestBuilder request = get("/app/xyz").contextPath("/app");
		this.mvc.perform(request).andExpect(status().isNotFound());
		MockHttpServletRequestBuilder getWithQuery = get("/app/xyz?def").contextPath("/app");
		this.mvc.perform(getWithQuery).andExpect(status().isFound());
		MockHttpServletRequestBuilder postWithQueryAndCsrf = post("/app/abc?def").with(csrf()).contextPath("/app");
		this.mvc.perform(postWithQueryAndCsrf).andExpect(status().isNotFound());
		MockHttpServletRequestBuilder getWithCsrf = get("/app/abc").with(csrf()).contextPath("/app");
		this.mvc.perform(getWithCsrf).andExpect(status().isFound());
	}

	@Test
	public void performWhenUsingPermitAllExactUrlRequestMatcherThenMatchesExactUrlWithAuthorizeHttp() throws Exception {
		this.spring.register(PermitAllConfigAuthorizeHttpRequests.class).autowire();
		MockHttpServletRequestBuilder request = get("/app/xyz").contextPath("/app");
		this.mvc.perform(request).andExpect(status().isNotFound());
		MockHttpServletRequestBuilder getWithQuery = get("/app/xyz?def").contextPath("/app");
		this.mvc.perform(getWithQuery).andExpect(status().isFound());
		MockHttpServletRequestBuilder postWithQueryAndCsrf = post("/app/abc?def").with(csrf()).contextPath("/app");
		this.mvc.perform(postWithQueryAndCsrf).andExpect(status().isNotFound());
		MockHttpServletRequestBuilder getWithCsrf = get("/app/abc").with(csrf()).contextPath("/app");
		this.mvc.perform(getWithCsrf).andExpect(status().isFound());
	}

	@Test
	public void configureWhenNotAuthorizeRequestsThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(NoAuthorizedUrlsConfig.class).autowire()).withMessageContaining(
						"permitAll only works with either HttpSecurity.authorizeRequests() or HttpSecurity.authorizeHttpRequests()");
	}

	@Test
	public void configureWhenBothAuthorizeRequestsAndAuthorizeHttpRequestsThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(PermitAllConfigWithBothConfigs.class).autowire())
				.withMessageContaining(
						"permitAll only works with either HttpSecurity.authorizeRequests() or HttpSecurity.authorizeHttpRequests()");
	}

	@Configuration
	@EnableWebSecurity
	static class PermitAllConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.formLogin()
					.loginPage("/xyz").permitAll()
					.loginProcessingUrl("/abc?def").permitAll();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class PermitAllConfigAuthorizeHttpRequests {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeHttpRequests()
						.anyRequest().authenticated()
						.and()
					.formLogin()
						.loginPage("/xyz").permitAll()
						.loginProcessingUrl("/abc?def").permitAll();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class PermitAllConfigWithBothConfigs {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeRequests()
						.anyRequest().authenticated()
						.and()
					.authorizeHttpRequests()
						.anyRequest().authenticated()
						.and()
					.formLogin()
						.loginPage("/xyz").permitAll()
						.loginProcessingUrl("/abc?def").permitAll();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class NoAuthorizedUrlsConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.permitAll();
			return http.build();
			// @formatter:on
		}

	}

}
