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
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link HttpBasicConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 */
public class HttpBasicConfigurerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnBasicAuthenticationFilter() {
		this.spring.register(ObjectPostProcessorConfig.class).autowire();

		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(BasicAuthenticationFilter.class));
	}

	@Test
	public void httpBasicWhenUsingDefaultsInLambdaThenResponseIncludesBasicChallenge() throws Exception {
		this.spring.register(DefaultsLambdaEntryPointConfig.class).autowire();

		this.mvc.perform(get("/")).andExpect(status().isUnauthorized())
				.andExpect(header().string("WWW-Authenticate", "Basic realm=\"Realm\""));
	}

	// SEC-2198
	@Test
	public void httpBasicWhenUsingDefaultsThenResponseIncludesBasicChallenge() throws Exception {
		this.spring.register(DefaultsEntryPointConfig.class).autowire();

		this.mvc.perform(get("/")).andExpect(status().isUnauthorized())
				.andExpect(header().string("WWW-Authenticate", "Basic realm=\"Realm\""));
	}

	@Test
	public void httpBasicWhenUsingCustomAuthenticationEntryPointThenResponseIncludesBasicChallenge() throws Exception {
		this.spring.register(CustomAuthenticationEntryPointConfig.class).autowire();

		this.mvc.perform(get("/"));

		verify(CustomAuthenticationEntryPointConfig.ENTRY_POINT).commence(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(AuthenticationException.class));
	}

	@Test
	public void httpBasicWhenInvokedTwiceThenUsesOriginalEntryPoint() throws Exception {
		this.spring.register(DuplicateDoesNotOverrideConfig.class).autowire();

		this.mvc.perform(get("/"));

		verify(DuplicateDoesNotOverrideConfig.ENTRY_POINT).commence(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(AuthenticationException.class));
	}

	// SEC-3019
	@Test
	public void httpBasicWhenRememberMeConfiguredThenSetsRememberMeCookie() throws Exception {
		this.spring.register(BasicUsesRememberMeConfig.class).autowire();

		this.mvc.perform(get("/").with(httpBasic("user", "password")).param("remember-me", "true"))
				.andExpect(cookie().exists("remember-me"));
	}

	@EnableWebSecurity
	static class ObjectPostProcessorConfig extends WebSecurityConfigurerAdapter {

		static ObjectPostProcessor<Object> objectPostProcessor = spy(ReflectingObjectPostProcessor.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic();
			// @formatter:on
		}

		@Bean
		static ObjectPostProcessor<Object> objectPostProcessor() {
			return objectPostProcessor;
		}

	}

	static class ReflectingObjectPostProcessor implements ObjectPostProcessor<Object> {

		@Override
		public <O> O postProcess(O object) {
			return object;
		}

	}

	@EnableWebSecurity
	static class DefaultsLambdaEntryPointConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().authenticated()
				)
				.httpBasic(withDefaults());
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class DefaultsEntryPointConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.httpBasic();
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class CustomAuthenticationEntryPointConfig extends WebSecurityConfigurerAdapter {

		static AuthenticationEntryPoint ENTRY_POINT = mock(AuthenticationEntryPoint.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.httpBasic()
					.authenticationEntryPoint(ENTRY_POINT);
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class DuplicateDoesNotOverrideConfig extends WebSecurityConfigurerAdapter {

		static AuthenticationEntryPoint ENTRY_POINT = mock(AuthenticationEntryPoint.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.httpBasic()
					.authenticationEntryPoint(ENTRY_POINT)
					.and()
				.httpBasic();
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	@Configuration
	static class BasicUsesRememberMeConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.rememberMe();
			// @formatter:on
		}

		@Override
		@Bean
		public UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(
			// @formatter:off
					User.withDefaultPasswordEncoder()
							.username("user")
							.password("password")
							.roles("USER")
							.build()
					// @formatter:on
			);
		}

	}

}
