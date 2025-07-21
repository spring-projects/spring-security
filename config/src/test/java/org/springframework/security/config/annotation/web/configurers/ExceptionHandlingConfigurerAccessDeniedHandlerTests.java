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
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.pathPattern;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Josh Cummings
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@SecurityTestExecutionListeners
public class ExceptionHandlingConfigurerAccessDeniedHandlerTests {

	@Autowired
	MockMvc mvc;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	@WithMockUser(roles = "ANYTHING")
	public void getWhenAccessDeniedOverriddenThenCustomizesResponseByRequest() throws Exception {
		this.spring.register(RequestMatcherBasedAccessDeniedHandlerConfig.class).autowire();
		this.mvc.perform(get("/hello")).andExpect(status().isIAmATeapot());
		this.mvc.perform(get("/goodbye")).andExpect(status().isForbidden());
	}

	@Test
	@WithMockUser(roles = "ANYTHING")
	public void getWhenAccessDeniedOverriddenInLambdaThenCustomizesResponseByRequest() throws Exception {
		this.spring.register(RequestMatcherBasedAccessDeniedHandlerInLambdaConfig.class).autowire();
		this.mvc.perform(get("/hello")).andExpect(status().isIAmATeapot());
		this.mvc.perform(get("/goodbye")).andExpect(status().isForbidden());
	}

	@Test
	@WithMockUser(roles = "ANYTHING")
	public void getWhenAccessDeniedOverriddenByOnlyOneHandlerThenAllRequestsUseThatHandler() throws Exception {
		this.spring.register(SingleRequestMatcherAccessDeniedHandlerConfig.class).autowire();
		this.mvc.perform(get("/hello")).andExpect(status().isIAmATeapot());
		this.mvc.perform(get("/goodbye")).andExpect(status().isIAmATeapot());
	}

	@Configuration
	@EnableWebSecurity
	static class RequestMatcherBasedAccessDeniedHandlerConfig {

		AccessDeniedHandler teapotDeniedHandler = (request, response, exception) -> response
			.setStatus(HttpStatus.I_AM_A_TEAPOT.value());

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.anyRequest().denyAll())
				.exceptionHandling((handling) -> handling
					.defaultAccessDeniedHandlerFor(
						this.teapotDeniedHandler,
							pathPattern("/hello/**"))
					.defaultAccessDeniedHandlerFor(
						new AccessDeniedHandlerImpl(),
						AnyRequestMatcher.INSTANCE));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RequestMatcherBasedAccessDeniedHandlerInLambdaConfig {

		AccessDeniedHandler teapotDeniedHandler = (request, response, exception) -> response
			.setStatus(HttpStatus.I_AM_A_TEAPOT.value());

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) -> authorize
						.anyRequest().denyAll()
				)
				.exceptionHandling((exceptionHandling) -> exceptionHandling
						.defaultAccessDeniedHandlerFor(
								this.teapotDeniedHandler,
								pathPattern("/hello/**")
						)
						.defaultAccessDeniedHandlerFor(
								new AccessDeniedHandlerImpl(),
								AnyRequestMatcher.INSTANCE
						)
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class SingleRequestMatcherAccessDeniedHandlerConfig {

		AccessDeniedHandler teapotDeniedHandler = (request, response, exception) -> response
			.setStatus(HttpStatus.I_AM_A_TEAPOT.value());

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.anyRequest().denyAll())
				.exceptionHandling((handling) -> handling
					.defaultAccessDeniedHandlerFor(
						this.teapotDeniedHandler,
							pathPattern("/hello/**")));
			return http.build();
			// @formatter:on
		}

	}

}
