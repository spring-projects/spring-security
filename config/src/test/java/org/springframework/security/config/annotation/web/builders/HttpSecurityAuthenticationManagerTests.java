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

package org.springframework.security.config.annotation.web.builders;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@ExtendWith(SpringTestContextExtension.class)
public class HttpSecurityAuthenticationManagerTests {

	@Autowired
	MockMvc mvc;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	public void authenticationManagerWhenConfiguredThenUsed() throws Exception {
		this.spring.register(AuthenticationManagerConfig.class).autowire();

		given(AuthenticationManagerConfig.AUTHENTICATION_MANAGER.authenticate(any()))
				.willReturn(new TestingAuthenticationToken("user", "test", "ROLE_USER"));

		this.mvc.perform(get("/").with(httpBasic("user", "test")));

		verify(AuthenticationManagerConfig.AUTHENTICATION_MANAGER).authenticate(any());
	}

	@Test
	public void authenticationManagerWhenBuilderAndAuthenticationManagerConfiguredThenBuilderIgnored()
			throws Exception {
		this.spring.register(AuthenticationManagerBuilderConfig.class).autowire();

		given(AuthenticationManagerBuilderConfig.AUTHENTICATION_MANAGER.authenticate(any()))
				.willReturn(new TestingAuthenticationToken("user", "test", "ROLE_USER"));

		this.mvc.perform(get("/").with(httpBasic("user", "test")));

		verify(AuthenticationManagerBuilderConfig.AUTHENTICATION_MANAGER).authenticate(any());
		verifyNoInteractions(AuthenticationManagerBuilderConfig.USER_DETAILS_SERVICE);
	}

	@Configuration
	@EnableWebSecurity
	static class AuthenticationManagerConfig {

		static final AuthenticationManager AUTHENTICATION_MANAGER = mock(AuthenticationManager.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeRequests((authz) -> authz
							.anyRequest().authenticated()
					)
					.httpBasic(withDefaults())
					.authenticationManager(AUTHENTICATION_MANAGER);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AuthenticationManagerBuilderConfig {

		static final AuthenticationManager AUTHENTICATION_MANAGER = mock(AuthenticationManager.class);
		static final UserDetailsService USER_DETAILS_SERVICE = mock(UserDetailsService.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeRequests((authz) -> authz
						.anyRequest().authenticated()
					)
					.httpBasic(withDefaults())
					.authenticationManager(AUTHENTICATION_MANAGER);
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return USER_DETAILS_SERVICE;
		}

	}

}
