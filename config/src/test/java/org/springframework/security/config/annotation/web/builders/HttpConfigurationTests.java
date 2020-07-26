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
package org.springframework.security.config.annotation.web.builders;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.ThrowableAssert.catchThrowable;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link HttpSecurity}.
 *
 * @author Rob Winch
 * @author Joe Grandja
 */
public class HttpConfigurationTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void configureWhenAddFilterUnregisteredThenThrowsBeanCreationException() {
		Throwable thrown = catchThrowable(() -> this.spring.register(UnregisteredFilterConfig.class).autowire());
		assertThat(thrown).isInstanceOf(BeanCreationException.class);
		assertThat(thrown.getMessage()).contains("The Filter class " + UnregisteredFilter.class.getName()
				+ " does not have a registered order and cannot be added without a specified order."
				+ " Consider using addFilterBefore or addFilterAfter instead.");
	}

	// https://github.com/spring-projects/spring-security-javaconfig/issues/104
	@Test
	public void configureWhenAddFilterCasAuthenticationFilterThenFilterAdded() throws Exception {
		CasAuthenticationFilterConfig.CAS_AUTHENTICATION_FILTER = spy(new CasAuthenticationFilter());
		this.spring.register(CasAuthenticationFilterConfig.class).autowire();

		this.mockMvc.perform(get("/"));

		verify(CasAuthenticationFilterConfig.CAS_AUTHENTICATION_FILTER).doFilter(any(ServletRequest.class),
				any(ServletResponse.class), any(FilterChain.class));
	}

	@Test
	public void configureWhenConfigIsRequestMatchersJavadocThenAuthorizationApplied() throws Exception {
		this.spring.register(RequestMatcherRegistryConfigs.class).autowire();

		this.mockMvc.perform(get("/oauth/a")).andExpect(status().isUnauthorized());
		this.mockMvc.perform(get("/oauth/b")).andExpect(status().isUnauthorized());
		this.mockMvc.perform(get("/api/a")).andExpect(status().isUnauthorized());
		this.mockMvc.perform(get("/api/b")).andExpect(status().isUnauthorized());
	}

	@EnableWebSecurity
	static class UnregisteredFilterConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) {
			// @formatter:off
			http
				.addFilter(new UnregisteredFilter());
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}

	}

	static class UnregisteredFilter extends OncePerRequestFilter {

		@Override
		protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
				FilterChain filterChain) throws ServletException, IOException {
			filterChain.doFilter(request, response);
		}

	}

	@EnableWebSecurity
	static class CasAuthenticationFilterConfig extends WebSecurityConfigurerAdapter {

		static CasAuthenticationFilter CAS_AUTHENTICATION_FILTER;

		@Override
		protected void configure(HttpSecurity http) {
			// @formatter:off
			http
				.addFilter(CAS_AUTHENTICATION_FILTER);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class RequestMatcherRegistryConfigs extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestMatchers()
					.antMatchers("/api/**")
					.antMatchers("/oauth/**")
					.and()
				.authorizeRequests()
					.antMatchers("/**").hasRole("USER")
					.and()
				.httpBasic();
			// @formatter:on
		}

	}

}
