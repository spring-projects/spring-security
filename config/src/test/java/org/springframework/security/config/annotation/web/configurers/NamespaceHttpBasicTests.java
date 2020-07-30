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

import org.apache.http.HttpHeaders;
import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.test.web.servlet.MockMvc;

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
public class NamespaceHttpBasicTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	/**
	 * http/http-basic equivalent
	 */
	@Test
	public void basicAuthenticationWhenUsingDefaultsThenMatchesNamespace() throws Exception {
		this.spring.register(HttpBasicConfig.class, UserConfig.class).autowire();

		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());

		this.mvc.perform(get("/").with(httpBasic("user", "invalid"))).andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Realm\""));

		this.mvc.perform(get("/").with(httpBasic("user", "password"))).andExpect(status().isNotFound());
	}

	@Test
	public void basicAuthenticationWhenUsingDefaultsInLambdaThenMatchesNamespace() throws Exception {
		this.spring.register(HttpBasicLambdaConfig.class, UserConfig.class).autowire();

		this.mvc.perform(get("/")).andExpect(status().isUnauthorized());

		this.mvc.perform(get("/").with(httpBasic("user", "invalid"))).andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Realm\""));

		this.mvc.perform(get("/").with(httpBasic("user", "password"))).andExpect(status().isNotFound());
	}

	/**
	 * http@realm equivalent
	 */
	@Test
	public void basicAuthenticationWhenUsingCustomRealmThenMatchesNamespace() throws Exception {
		this.spring.register(CustomHttpBasicConfig.class, UserConfig.class).autowire();

		this.mvc.perform(get("/").with(httpBasic("user", "invalid"))).andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Custom Realm\""));
	}

	@Test
	public void basicAuthenticationWhenUsingCustomRealmInLambdaThenMatchesNamespace() throws Exception {
		this.spring.register(CustomHttpBasicLambdaConfig.class, UserConfig.class).autowire();

		this.mvc.perform(get("/").with(httpBasic("user", "invalid"))).andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Custom Realm\""));
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

	@EnableWebSecurity
	static class HttpBasicConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.httpBasic();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class HttpBasicLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().hasRole("USER")
				)
				.httpBasic(withDefaults());
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class CustomHttpBasicConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.httpBasic().realmName("Custom Realm");
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class CustomHttpBasicLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().hasRole("USER")
				)
				.httpBasic((httpBasicConfig) -> httpBasicConfig.realmName("Custom Realm"));
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class AuthenticationDetailsSourceHttpBasicConfig extends WebSecurityConfigurerAdapter {

		AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = mock(
				AuthenticationDetailsSource.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.authenticationDetailsSource(this.authenticationDetailsSource);
			// @formatter:on
		}

		@Bean
		AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
			return this.authenticationDetailsSource;
		}

	}

	@EnableWebSecurity
	static class AuthenticationDetailsSourceHttpBasicLambdaConfig extends WebSecurityConfigurerAdapter {

		AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = mock(
				AuthenticationDetailsSource.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic((httpBasicConfig) ->
						httpBasicConfig.authenticationDetailsSource(this.authenticationDetailsSource));
			// @formatter:on
		}

		@Bean
		AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
			return this.authenticationDetailsSource;
		}

	}

	@EnableWebSecurity
	static class EntryPointRefHttpBasicConfig extends WebSecurityConfigurerAdapter {

		AuthenticationEntryPoint authenticationEntryPoint = (request, response, ex) -> response.setStatus(999);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.httpBasic()
					.authenticationEntryPoint(this.authenticationEntryPoint);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class EntryPointRefHttpBasicLambdaConfig extends WebSecurityConfigurerAdapter {

		AuthenticationEntryPoint authenticationEntryPoint = (request, response, ex) -> response.setStatus(999);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().hasRole("USER")
				)
				.httpBasic((httpBasicConfig) ->
						httpBasicConfig.authenticationEntryPoint(this.authenticationEntryPoint));
			// @formatter:on
		}

	}

}
