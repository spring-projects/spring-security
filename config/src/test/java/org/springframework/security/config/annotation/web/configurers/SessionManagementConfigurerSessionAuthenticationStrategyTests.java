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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;

/**
 * @author Joe Grandja
 */
@ExtendWith(SpringTestContextExtension.class)
public class SessionManagementConfigurerSessionAuthenticationStrategyTests {

	@Autowired
	private MockMvc mvc;

	public final SpringTestContext spring = new SpringTestContext(this);

	// gh-5763
	@Test
	public void requestWhenCustomSessionAuthenticationStrategyProvidedThenCalled() throws Exception {
		this.spring.register(CustomSessionAuthenticationStrategyConfig.class).autowire();
		this.mvc.perform(formLogin().user("user").password("password"));
		verify(CustomSessionAuthenticationStrategyConfig.customSessionAuthenticationStrategy).onAuthentication(
				any(Authentication.class), any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Configuration
	@EnableWebSecurity
	static class CustomSessionAuthenticationStrategyConfig {

		static SessionAuthenticationStrategy customSessionAuthenticationStrategy = mock(
				SessionAuthenticationStrategy.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.and()
				.sessionManagement()
					.sessionAuthenticationStrategy(customSessionAuthenticationStrategy);
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

}
