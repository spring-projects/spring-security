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

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.assertj.core.api.ListAssert;
import org.junit.Rule;
import org.junit.Test;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests to verify that all the functionality of &lt;custom-filter&gt; attributes is
 * present
 *
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
public class NamespaceHttpCustomFilterTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Test
	public void getFiltersWhenFilterAddedBeforeThenBehaviorMatchesNamespace() {
		this.spring.register(CustomFilterBeforeConfig.class, UserDetailsServiceConfig.class).autowire();
		assertThatFilters().containsSubsequence(CustomFilter.class, UsernamePasswordAuthenticationFilter.class);
	}

	@EnableWebSecurity
	static class CustomFilterBeforeConfig extends WebSecurityConfigurerAdapter {

		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.addFilterBefore(new CustomFilter(), UsernamePasswordAuthenticationFilter.class)
				.formLogin();
			// @formatter:on
		}

	}

	@Test
	public void getFiltersWhenFilterAddedAfterThenBehaviorMatchesNamespace() {
		this.spring.register(CustomFilterAfterConfig.class, UserDetailsServiceConfig.class).autowire();
		assertThatFilters().containsSubsequence(UsernamePasswordAuthenticationFilter.class, CustomFilter.class);
	}

	@EnableWebSecurity
	static class CustomFilterAfterConfig extends WebSecurityConfigurerAdapter {

		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.addFilterAfter(new CustomFilter(), UsernamePasswordAuthenticationFilter.class)
				.formLogin();
			// @formatter:on
		}

	}

	@Test
	public void getFiltersWhenFilterAddedThenBehaviorMatchesNamespace() {
		this.spring.register(CustomFilterPositionConfig.class, UserDetailsServiceConfig.class).autowire();
		assertThatFilters().containsExactly(CustomFilter.class);
	}

	@EnableWebSecurity
	static class CustomFilterPositionConfig extends WebSecurityConfigurerAdapter {

		CustomFilterPositionConfig() {
			// do not add the default filters to make testing easier
			super(true);
		}

		protected void configure(HttpSecurity http) {
			// @formatter:off
			http
				// this works so long as the CustomFilter extends one of the standard filters
				// if not, use addFilterBefore or addFilterAfter
				.addFilter(new CustomFilter());
			// @formatter:on
		}

	}

	@Test
	public void getFiltersWhenFilterAddedAtPositionThenBehaviorMatchesNamespace() {
		this.spring.register(CustomFilterPositionAtConfig.class, UserDetailsServiceConfig.class).autowire();
		assertThatFilters().containsExactly(OtherCustomFilter.class);
	}

	@EnableWebSecurity
	static class CustomFilterPositionAtConfig extends WebSecurityConfigurerAdapter {

		CustomFilterPositionAtConfig() {
			// do not add the default filters to make testing easier
			super(true);
		}

		protected void configure(HttpSecurity http) {
			// @formatter:off
			http
				.addFilterAt(new OtherCustomFilter(), UsernamePasswordAuthenticationFilter.class);
			// @formatter:on
		}

	}

	@Test
	public void getFiltersWhenCustomAuthenticationManagerThenBehaviorMatchesNamespace() {
		this.spring.register(NoAuthenticationManagerInHttpConfigurationConfig.class).autowire();
		assertThatFilters().startsWith(CustomFilter.class);
	}

	@EnableWebSecurity
	static class NoAuthenticationManagerInHttpConfigurationConfig extends WebSecurityConfigurerAdapter {

		NoAuthenticationManagerInHttpConfigurationConfig() {
			super(true);
		}

		protected AuthenticationManager authenticationManager() {
			return new CustomAuthenticationManager();
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.addFilterBefore(new CustomFilter(), UsernamePasswordAuthenticationFilter.class);
			// @formatter:on
		}

	}

	@Configuration
	static class UserDetailsServiceConfig {

		@Bean
		public UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(
			// @formatter:off
					User.withDefaultPasswordEncoder()
							.username("user")
							.password("password")
							.roles("USER")
							.build());
					// @formatter:on
		}

	}

	static class CustomFilter extends UsernamePasswordAuthenticationFilter {

	}

	static class OtherCustomFilter extends OncePerRequestFilter {

		protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
				FilterChain filterChain) throws ServletException, IOException {
			filterChain.doFilter(request, response);
		}

	}

	static class CustomAuthenticationManager implements AuthenticationManager {

		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			return null;
		}

	}

	private ListAssert<Class<?>> assertThatFilters() {
		FilterChainProxy filterChain = this.spring.getContext().getBean(FilterChainProxy.class);
		List<Class<?>> filters = filterChain.getFilters("/").stream().map(Object::getClass)
				.collect(Collectors.toList());
		return assertThat(filters);
	}

}
