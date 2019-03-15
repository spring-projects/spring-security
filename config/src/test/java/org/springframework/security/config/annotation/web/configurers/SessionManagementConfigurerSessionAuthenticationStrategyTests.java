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
package org.springframework.security.config.annotation.web.configurers;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.test.web.servlet.MockMvc;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;

/**
 * @author Joe Grandja
 */
public class SessionManagementConfigurerSessionAuthenticationStrategyTests {

	@Autowired
	private MockMvc mvc;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	// gh-5763
	@Test
	public void requestWhenCustomSessionAuthenticationStrategyProvidedThenCalled() throws Exception {
		this.spring.register(CustomSessionAuthenticationStrategyConfig.class).autowire();
		this.mvc.perform(formLogin().user("user").password("password"));
		verify(CustomSessionAuthenticationStrategyConfig.customSessionAuthenticationStrategy)
				.onAuthentication(any(Authentication.class), any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@EnableWebSecurity
	static class CustomSessionAuthenticationStrategyConfig extends WebSecurityConfigurerAdapter {
		static SessionAuthenticationStrategy customSessionAuthenticationStrategy = mock(SessionAuthenticationStrategy.class);

		// @formatter:off
		@Override
		public void configure(HttpSecurity http) throws Exception {
			http
				.formLogin()
					.and()
				.sessionManagement()
					.sessionAuthenticationStrategy(customSessionAuthenticationStrategy);
		}
		// @formatter:on

		// @formatter:off
		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
		}
		// @formatter:on
	}
}
