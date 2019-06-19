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


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests to verify that all the functionality of <access-denied-handler> attributes is present
 *
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
public class NamespaceHttpServerAccessDeniedHandlerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void requestWhenCustomAccessDeniedPageThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(AccessDeniedPageConfig.class).autowire();
		this.mvc.perform(get("/")
				.with(authentication(user())))
				.andExpect(status().isForbidden())
				.andExpect(forwardedUrl("/AccessDeniedPageConfig"));
	}

	@EnableWebSecurity
	static class AccessDeniedPageConfig extends WebSecurityConfigurerAdapter {
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().denyAll()
					.and()
				.exceptionHandling()
					.accessDeniedPage("/AccessDeniedPageConfig");
		}
	}

	private static Authentication user() {
		return new UsernamePasswordAuthenticationToken("user", null, AuthorityUtils.NO_AUTHORITIES);
	}

	@Test
	public void requestWhenCustomAccessDeniedPageInLambdaThenForwardedToCustomPage() throws Exception {
		this.spring.register(AccessDeniedPageInLambdaConfig.class).autowire();

		this.mvc.perform(get("/")
				.with(authentication(user())))
				.andExpect(status().isForbidden())
				.andExpect(forwardedUrl("/AccessDeniedPageConfig"));
	}

	@EnableWebSecurity
	static class AccessDeniedPageInLambdaConfig extends WebSecurityConfigurerAdapter {
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().denyAll()
					.and()
				.exceptionHandling(exceptionHandling ->
					exceptionHandling.accessDeniedPage("/AccessDeniedPageConfig")
				);
			// @formatter:on
		}
	}

	@Test
	public void requestWhenCustomAccessDeniedHandlerThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(AccessDeniedHandlerRefConfig.class).autowire();
		this.mvc.perform(get("/")
				.with(authentication(user())));
		verifyBean(AccessDeniedHandler.class)
				.handle(any(HttpServletRequest.class), any(HttpServletResponse.class), any(AccessDeniedException.class));
	}

	@EnableWebSecurity
	static class AccessDeniedHandlerRefConfig extends WebSecurityConfigurerAdapter {
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().denyAll()
					.and()
				.exceptionHandling()
					.accessDeniedHandler(accessDeniedHandler());
		}

		@Bean
		AccessDeniedHandler accessDeniedHandler() {
			return mock(AccessDeniedHandler.class);
		}
	}

	@Test
	public void requestWhenCustomAccessDeniedHandlerInLambdaThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(AccessDeniedHandlerRefInLambdaConfig.class).autowire();

		this.mvc.perform(get("/")
				.with(authentication(user())));

		verify(AccessDeniedHandlerRefInLambdaConfig.accessDeniedHandler)
				.handle(any(HttpServletRequest.class), any(HttpServletResponse.class), any(AccessDeniedException.class));
	}

	@EnableWebSecurity
	static class AccessDeniedHandlerRefInLambdaConfig extends WebSecurityConfigurerAdapter {
		static AccessDeniedHandler accessDeniedHandler = mock(AccessDeniedHandler.class);

		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().denyAll()
					.and()
				.exceptionHandling(exceptionHandling ->
						exceptionHandling.accessDeniedHandler(accessDeniedHandler())
				);
			// @formatter:on
		}

		@Bean
		AccessDeniedHandler accessDeniedHandler() {
			return accessDeniedHandler;
		}
	}

	private <T> T verifyBean(Class<T> beanClass) {
		return verify(this.spring.getContext().getBean(beanClass));
	}
}
