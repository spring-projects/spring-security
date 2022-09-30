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

package org.springframework.security.config.annotation.authentication;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;

/**
 * @author Rob Winch
 */
@ExtendWith(SpringTestContextExtension.class)
public class PasswordEncoderConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void passwordEncoderRefWhenNoAuthenticationManagerBeanThenNoExceptionThrown() {
		this.spring.register(PasswordEncoderConfig.class).autowire();
	}

	@Test
	public void passwordEncoderRefWhenAuthenticationManagerBuilderThenAuthenticationSuccess() throws Exception {
		this.spring.register(PasswordEncoderNoAuthManagerLoadsConfig.class).autowire();
		this.mockMvc.perform(formLogin()).andExpect(authenticated());
	}

	@Configuration
	@EnableWebSecurity
	static class PasswordEncoderConfig {

		@Autowired
		void configure(AuthenticationManagerBuilder auth) throws Exception {
			BCryptPasswordEncoder encoder = passwordEncoder();
			// @formatter:off
			auth
					.inMemoryAuthentication()
					.withUser("user").password(encoder.encode("password")).roles("USER").and()
					.passwordEncoder(encoder);
			// @formatter:on
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			return http.build();
		}

		@Bean
		BCryptPasswordEncoder passwordEncoder() {
			return new BCryptPasswordEncoder();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class PasswordEncoderNoAuthManagerLoadsConfig {

		@Autowired
		void configure(AuthenticationManagerBuilder auth) throws Exception {
			BCryptPasswordEncoder encoder = passwordEncoder();
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser("user").password(encoder.encode("password")).roles("USER").and()
					.passwordEncoder(encoder);
			// @formatter:on
		}

		@Bean
		BCryptPasswordEncoder passwordEncoder() {
			return new BCryptPasswordEncoder();
		}

	}

}
