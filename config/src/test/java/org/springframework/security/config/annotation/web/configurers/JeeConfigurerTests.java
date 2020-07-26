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

import java.security.Principal;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.preauth.j2ee.J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.preauth.j2ee.J2eePreAuthenticatedProcessingFilter;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * Tests for {@link JeeConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 */
public class JeeConfigurerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnJ2eePreAuthenticatedProcessingFilter() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();

		verify(ObjectPostProcessorConfig.objectPostProcessor)
				.postProcess(any(J2eePreAuthenticatedProcessingFilter.class));
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnJ2eeBasedPreAuthenticatedWebAuthenticationDetailsSource() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();

		verify(ObjectPostProcessorConfig.objectPostProcessor)
				.postProcess(any(J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource.class));
	}

	@Test
	public void jeeWhenInvokedTwiceThenUsesOriginalMappableRoles() throws Exception {
		this.spring.register(InvokeTwiceDoesNotOverride.class).autowire();
		Principal user = mock(Principal.class);
		when(user.getName()).thenReturn("user");

		this.mvc.perform(get("/").principal(user).with(request -> {
			request.addUserRole("ROLE_ADMIN");
			request.addUserRole("ROLE_USER");
			return request;
		})).andExpect(authenticated().withRoles("USER"));
	}

	@Test
	public void requestWhenJeeMappableRolesInLambdaThenAuthenticatedWithMappableRoles() throws Exception {
		this.spring.register(JeeMappableRolesConfig.class).autowire();
		Principal user = mock(Principal.class);
		when(user.getName()).thenReturn("user");

		this.mvc.perform(get("/").principal(user).with(request -> {
			request.addUserRole("ROLE_ADMIN");
			request.addUserRole("ROLE_USER");
			return request;
		})).andExpect(authenticated().withRoles("USER"));
	}

	@Test
	public void requestWhenJeeMappableAuthoritiesInLambdaThenAuthenticatedWithMappableAuthorities() throws Exception {
		this.spring.register(JeeMappableAuthoritiesConfig.class).autowire();
		Principal user = mock(Principal.class);
		when(user.getName()).thenReturn("user");

		this.mvc.perform(get("/").principal(user).with(request -> {
			request.addUserRole("ROLE_ADMIN");
			request.addUserRole("ROLE_USER");
			return request;
		})).andExpect(authenticated().withAuthorities(AuthorityUtils.createAuthorityList("ROLE_USER")));
	}

	@Test
	public void requestWhenCustomAuthenticatedUserDetailsServiceInLambdaThenCustomAuthenticatedUserDetailsServiceUsed()
			throws Exception {
		this.spring.register(JeeCustomAuthenticatedUserDetailsServiceConfig.class).autowire();
		Principal user = mock(Principal.class);
		User userDetails = new User("user", "N/A", true, true, true, true,
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		when(user.getName()).thenReturn("user");
		when(JeeCustomAuthenticatedUserDetailsServiceConfig.authenticationUserDetailsService.loadUserDetails(any()))
				.thenReturn(userDetails);

		this.mvc.perform(get("/").principal(user).with(request -> {
			request.addUserRole("ROLE_ADMIN");
			request.addUserRole("ROLE_USER");
			return request;
		})).andExpect(authenticated().withRoles("USER"));
	}

	@EnableWebSecurity
	static class ObjectPostProcessorConfig extends WebSecurityConfigurerAdapter {

		static ObjectPostProcessor<Object> objectPostProcessor;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.jee();
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
	static class InvokeTwiceDoesNotOverride extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.jee()
					.mappableRoles("USER")
					.and()
				.jee();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	public static class JeeMappableRolesConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().hasRole("USER")
				)
				.jee(jee ->
					jee
						.mappableRoles("USER")
				);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	public static class JeeMappableAuthoritiesConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().hasRole("USER")
				)
				.jee(jee ->
					jee
						.mappableAuthorities("ROLE_USER")
				);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	public static class JeeCustomAuthenticatedUserDetailsServiceConfig extends WebSecurityConfigurerAdapter {

		static AuthenticationUserDetailsService authenticationUserDetailsService = mock(
				AuthenticationUserDetailsService.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().hasRole("USER")
				)
				.jee(jee ->
					jee
						.authenticatedUserDetailsService(authenticationUserDetailsService)
				);
			// @formatter:on
		}

	}

}
