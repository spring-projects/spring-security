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
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rob Winch
 * @author Josh Cummings
 */
public class AnonymousConfigurerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void requestWhenAnonymousTwiceInvokedThenDoesNotOverride() throws Exception {
		this.spring.register(InvokeTwiceDoesNotOverride.class, PrincipalController.class).autowire();

		this.mockMvc.perform(get("/")).andExpect(content().string("principal"));
	}

	@Test
	public void requestWhenAnonymousPrincipalInLambdaThenPrincipalUsed() throws Exception {
		this.spring.register(AnonymousPrincipalInLambdaConfig.class, PrincipalController.class).autowire();

		this.mockMvc.perform(get("/")).andExpect(content().string("principal"));
	}

	@Test
	public void requestWhenAnonymousDisabledInLambdaThenRespondsWithForbidden() throws Exception {
		this.spring.register(AnonymousDisabledInLambdaConfig.class, PrincipalController.class).autowire();

		this.mockMvc.perform(get("/")).andExpect(status().isForbidden());
	}

	@Test
	public void requestWhenAnonymousWithDefaultsInLambdaThenRespondsWithOk() throws Exception {
		this.spring.register(AnonymousWithDefaultsInLambdaConfig.class, PrincipalController.class).autowire();

		this.mockMvc.perform(get("/")).andExpect(status().isOk());
	}

	@EnableWebSecurity
	@EnableWebMvc
	static class InvokeTwiceDoesNotOverride extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.anonymous()
					.key("key")
					.principal("principal")
					.and()
				.anonymous();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	@EnableWebMvc
	static class AnonymousPrincipalInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.anonymous(anonymous ->
					anonymous
						.principal("principal")
				);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class AnonymousDisabledInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().permitAll()
				)
				.anonymous(AbstractHttpConfigurer::disable);
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class AnonymousWithDefaultsInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().permitAll()
				)
				.anonymous(withDefaults());
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

	}

	@RestController
	static class PrincipalController {

		@GetMapping("/")
		String principal(@AuthenticationPrincipal String principal) {
			return principal;
		}

	}

}
