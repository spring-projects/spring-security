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

package org.springframework.security.config.annotation.authentication;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;

/**
 * @author Rob Winch
 */
public class PasswordEncoderConfigurerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void passwordEncoderRefWhenNoAuthenticationManagerBeanThenNoExceptionThrown() {
		this.spring.register(PasswordEncoderConfig.class).autowire();
	}

	@EnableWebSecurity
	static class PasswordEncoderConfig extends WebSecurityConfigurerAdapter {

		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			BCryptPasswordEncoder encoder = passwordEncoder();
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser("user").password(encoder.encode("password")).roles("USER").and()
					.passwordEncoder(encoder);
			// @formatter:on
		}

		@Override
		protected void configure(HttpSecurity http) {
		}

		@Bean
		public BCryptPasswordEncoder passwordEncoder() {
			return new BCryptPasswordEncoder();
		}

	}

	@Test
	public void passwordEncoderRefWhenAuthenticationManagerBuilderThenAuthenticationSuccess() throws Exception {
		this.spring.register(PasswordEncoderNoAuthManagerLoadsConfig.class).autowire();

		this.mockMvc.perform(formLogin()).andExpect(authenticated());
	}

	@EnableWebSecurity
	static class PasswordEncoderNoAuthManagerLoadsConfig extends WebSecurityConfigurerAdapter {

		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			BCryptPasswordEncoder encoder = passwordEncoder();
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser("user").password(encoder.encode("password")).roles("USER").and()
					.passwordEncoder(encoder);
			// @formatter:on
		}

		@Bean
		public BCryptPasswordEncoder passwordEncoder() {
			return new BCryptPasswordEncoder();
		}

	}

}
