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
import org.apache.http.HttpHeaders;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests to verify that all the functionality of &lt;http-basic&gt; attributes is present
 *
 * @author Rob Winch
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension.class)
public class NamespaceHttpBasicTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	/**
	 * http/http-basic equivalent
	 */
	@Test
	public void basicAuthenticationWhenUsingDefaultsThenMatchesNamespace() throws Exception {
		this.spring.register(HttpBasicConfig.class, UserConfig.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
		MockHttpServletRequestBuilder requestWithInvalidPassword = get("/").with(httpBasic("user", "invalid"));
		// @formatter:off
		this.mvc.perform(requestWithInvalidPassword)
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Realm\""));
		// @formatter:on
		MockHttpServletRequestBuilder requestWithValidPassword = get("/").with(httpBasic("user", "password"));
		this.mvc.perform(requestWithValidPassword).andExpect(status().isNotFound());
	}

	@Test
	public void basicAuthenticationWhenUsingDefaultsInLambdaThenMatchesNamespace() throws Exception {
		this.spring.register(HttpBasicLambdaConfig.class, UserConfig.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());
		MockHttpServletRequestBuilder requestWithInvalidPassword = get("/").with(httpBasic("user", "invalid"));
		// @formatter:off
		this.mvc.perform(requestWithInvalidPassword)
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Realm\""));
		// @formatter:on
		MockHttpServletRequestBuilder requestWithValidPassword = get("/").with(httpBasic("user", "password"));
		this.mvc.perform(requestWithValidPassword).andExpect(status().isNotFound());
	}

	/**
	 * http@realm equivalent
	 */
	@Test
	public void basicAuthenticationWhenUsingCustomRealmThenMatchesNamespace() throws Exception {
		this.spring.register(CustomHttpBasicConfig.class, UserConfig.class).autowire();
		MockHttpServletRequestBuilder requestWithInvalidPassword = get("/").with(httpBasic("user", "invalid"));
		// @formatter:off
		this.mvc.perform(requestWithInvalidPassword)
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Custom Realm\""));
		// @formatter:on
	}

	@Test
	public void basicAuthenticationWhenUsingCustomRealmInLambdaThenMatchesNamespace() throws Exception {
		this.spring.register(CustomHttpBasicLambdaConfig.class, UserConfig.class).autowire();
		MockHttpServletRequestBuilder requestWithInvalidPassword = get("/").with(httpBasic("user", "invalid"));
		// @formatter:off
		this.mvc.perform(requestWithInvalidPassword)
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Custom Realm\""));
		// @formatter:on
	}

	/**
	 * http/http-basic@authentication-details-source-ref equivalent
	 */
	@Test
	public void basicAuthenticationWhenUsingAuthenticationDetailsSourceRefThenMatchesNamespace() throws Exception {
		this.spring.register(AuthenticationDetailsSourceHttpBasicConfig.class, UserConfig.class).autowire();
		AuthenticationDetailsSource<HttpServletRequest, ?> source = this.spring.getContext()
				.getBean(AuthenticationDetailsSource.class);
		this.mvc.perform(get("/").with(httpBasic("user", "password")));
		verify(source).buildDetails(any(HttpServletRequest.class));
	}

	@Test
	public void basicAuthenticationWhenUsingAuthenticationDetailsSourceRefInLambdaThenMatchesNamespace()
			throws Exception {
		this.spring.register(AuthenticationDetailsSourceHttpBasicLambdaConfig.class, UserConfig.class).autowire();
		AuthenticationDetailsSource<HttpServletRequest, ?> source = this.spring.getContext()
				.getBean(AuthenticationDetailsSource.class);
		this.mvc.perform(get("/").with(httpBasic("user", "password")));
		verify(source).buildDetails(any(HttpServletRequest.class));
	}

	/**
	 * http/http-basic@entry-point-ref
	 */
	@Test
	public void basicAuthenticationWhenUsingEntryPointRefThenMatchesNamespace() throws Exception {
		this.spring.register(EntryPointRefHttpBasicConfig.class, UserConfig.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().is(999));
		this.mvc.perform(get("/").with(httpBasic("user", "invalid"))).andExpect(status().is(999));
		this.mvc.perform(get("/").with(httpBasic("user", "password"))).andExpect(status().isNotFound());
	}

	@Test
	public void basicAuthenticationWhenUsingEntryPointRefInLambdaThenMatchesNamespace() throws Exception {
		this.spring.register(EntryPointRefHttpBasicLambdaConfig.class, UserConfig.class).autowire();
		this.mvc.perform(get("/")).andExpect(status().is(999));
		this.mvc.perform(get("/").with(httpBasic("user", "invalid"))).andExpect(status().is(999));
		this.mvc.perform(get("/").with(httpBasic("user", "password"))).andExpect(status().isNotFound());
	}

	@Configuration
	static class UserConfig {

		@Bean
		UserDetailsService userDetailsService() {
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

	@Configuration
	@EnableWebSecurity
	static class HttpBasicConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.httpBasic();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HttpBasicLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().hasRole("USER")
				)
				.httpBasic(withDefaults());
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomHttpBasicConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.httpBasic().realmName("Custom Realm");
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomHttpBasicLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().hasRole("USER")
				)
				.httpBasic((httpBasicConfig) -> httpBasicConfig.realmName("Custom Realm"));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AuthenticationDetailsSourceHttpBasicConfig {

		AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = mock(
				AuthenticationDetailsSource.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.authenticationDetailsSource(this.authenticationDetailsSource);
			return http.build();
			// @formatter:on
		}

		@Bean
		AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
			return this.authenticationDetailsSource;
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AuthenticationDetailsSourceHttpBasicLambdaConfig {

		AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = mock(
				AuthenticationDetailsSource.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic((httpBasicConfig) ->
						httpBasicConfig.authenticationDetailsSource(this.authenticationDetailsSource));
			return http.build();
			// @formatter:on
		}

		@Bean
		AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
			return this.authenticationDetailsSource;
		}

	}

	@Configuration
	@EnableWebSecurity
	static class EntryPointRefHttpBasicConfig {

		AuthenticationEntryPoint authenticationEntryPoint = (request, response, ex) -> response.setStatus(999);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.httpBasic()
					.authenticationEntryPoint(this.authenticationEntryPoint);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class EntryPointRefHttpBasicLambdaConfig {

		AuthenticationEntryPoint authenticationEntryPoint = (request, response, ex) -> response.setStatus(999);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().hasRole("USER")
				)
				.httpBasic((httpBasicConfig) ->
						httpBasicConfig.authenticationEntryPoint(this.authenticationEntryPoint));
			return http.build();
			// @formatter:on
		}

	}

}
