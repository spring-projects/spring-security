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
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Josh Cummings
 */
@RunWith(SpringJUnit4ClassRunner.class)
@SecurityTestExecutionListeners
public class ExceptionHandlingConfigurerAccessDeniedHandlerTests {
	@Autowired
	MockMvc mvc;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Test
	@WithMockUser(roles = "ANYTHING")
	public void getWhenAccessDeniedOverriddenThenCustomizesResponseByRequest()
			throws Exception {
		this.spring.register(RequestMatcherBasedAccessDeniedHandlerConfig.class).autowire();

		this.mvc.perform(get("/hello"))
				.andExpect(status().isIAmATeapot());

		this.mvc.perform(get("/goodbye"))
				.andExpect(status().isForbidden());
	}

	@EnableWebSecurity
	static class RequestMatcherBasedAccessDeniedHandlerConfig extends WebSecurityConfigurerAdapter {
		AccessDeniedHandler teapotDeniedHandler =
				(request, response, exception) ->
						response.setStatus(HttpStatus.I_AM_A_TEAPOT.value());

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().denyAll()
					.and()
				.exceptionHandling()
					.defaultAccessDeniedHandlerFor(
							this.teapotDeniedHandler,
							new AntPathRequestMatcher("/hello/**"))
					.defaultAccessDeniedHandlerFor(
							new AccessDeniedHandlerImpl(),
							AnyRequestMatcher.INSTANCE);
			// @formatter:on
		}
	}

	@Test
	@WithMockUser(roles = "ANYTHING")
	public void getWhenAccessDeniedOverriddenInLambdaThenCustomizesResponseByRequest()
			throws Exception {
		this.spring.register(RequestMatcherBasedAccessDeniedHandlerInLambdaConfig.class).autowire();

		this.mvc.perform(get("/hello"))
				.andExpect(status().isIAmATeapot());

		this.mvc.perform(get("/goodbye"))
				.andExpect(status().isForbidden());
	}

	@EnableWebSecurity
	static class RequestMatcherBasedAccessDeniedHandlerInLambdaConfig extends WebSecurityConfigurerAdapter {
		AccessDeniedHandler teapotDeniedHandler =
				(request, response, exception) ->
						response.setStatus(HttpStatus.I_AM_A_TEAPOT.value());

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().denyAll()
				)
				.exceptionHandling(exceptionHandling ->
					exceptionHandling
						.defaultAccessDeniedHandlerFor(
								this.teapotDeniedHandler,
								new AntPathRequestMatcher("/hello/**")
						)
						.defaultAccessDeniedHandlerFor(
								new AccessDeniedHandlerImpl(),
								AnyRequestMatcher.INSTANCE
						)
				);
			// @formatter:on
		}
	}

	@Test
	@WithMockUser(roles = "ANYTHING")
	public void getWhenAccessDeniedOverriddenByOnlyOneHandlerThenAllRequestsUseThatHandler()
			throws Exception {
		this.spring.register(SingleRequestMatcherAccessDeniedHandlerConfig.class).autowire();

		this.mvc.perform(get("/hello"))
				.andExpect(status().isIAmATeapot());

		this.mvc.perform(get("/goodbye"))
				.andExpect(status().isIAmATeapot());
	}

	@EnableWebSecurity
	static class SingleRequestMatcherAccessDeniedHandlerConfig extends WebSecurityConfigurerAdapter {
		AccessDeniedHandler teapotDeniedHandler =
				(request, response, exception) ->
						response.setStatus(HttpStatus.I_AM_A_TEAPOT.value());

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeRequests()
					.anyRequest().denyAll()
					.and()
					.exceptionHandling()
					.defaultAccessDeniedHandlerFor(
							this.teapotDeniedHandler,
							new AntPathRequestMatcher("/hello/**"));
			// @formatter:on
		}
	}
}
