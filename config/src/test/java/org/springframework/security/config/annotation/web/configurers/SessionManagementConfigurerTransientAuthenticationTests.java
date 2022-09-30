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
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.Transient;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension.class)
public class SessionManagementConfigurerTransientAuthenticationTests {

	@Autowired
	MockMvc mvc;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	public void postWhenTransientAuthenticationThenNoSessionCreated() throws Exception {
		this.spring.register(WithTransientAuthenticationConfig.class).autowire();
		MvcResult result = this.mvc.perform(post("/login")).andReturn();
		assertThat(result.getRequest().getSession(false)).isNull();
	}

	@Test
	public void postWhenTransientAuthenticationThenAlwaysSessionOverrides() throws Exception {
		this.spring.register(AlwaysCreateSessionConfig.class).autowire();
		MvcResult result = this.mvc.perform(post("/login")).andReturn();
		assertThat(result.getRequest().getSession(false)).isNotNull();
	}

	@Configuration
	@EnableWebSecurity
	static class WithTransientAuthenticationConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf().disable()
				.authenticationProvider(new TransientAuthenticationProvider());
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AlwaysCreateSessionConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
			return http.build();
			// @formatter:on
		}

	}

	static class TransientAuthenticationProvider implements AuthenticationProvider {

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			return new SomeTransientAuthentication();
		}

		@Override
		public boolean supports(Class<?> authentication) {
			return true;
		}

	}

	@Transient
	static class SomeTransientAuthentication extends AbstractAuthenticationToken {

		SomeTransientAuthentication() {
			super(null);
		}

		@Override
		public Object getCredentials() {
			return null;
		}

		@Override
		public Object getPrincipal() {
			return null;
		}

	}

}
