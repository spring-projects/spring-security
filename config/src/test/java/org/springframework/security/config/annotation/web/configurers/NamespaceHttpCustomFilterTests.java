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

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.assertj.core.api.ListAssert;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.TestHttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
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
@ExtendWith(SpringTestContextExtension.class)
public class NamespaceHttpCustomFilterTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	public void getFiltersWhenFilterAddedBeforeThenBehaviorMatchesNamespace() {
		this.spring.register(CustomFilterBeforeConfig.class, UserDetailsServiceConfig.class).autowire();
		assertThatFilters().containsSubsequence(CustomFilter.class, UsernamePasswordAuthenticationFilter.class);
	}

	@Test
	public void getFiltersWhenFilterAddedAfterThenBehaviorMatchesNamespace() {
		this.spring.register(CustomFilterAfterConfig.class, UserDetailsServiceConfig.class).autowire();
		assertThatFilters().containsSubsequence(UsernamePasswordAuthenticationFilter.class, CustomFilter.class);
	}

	@Test
	public void getFiltersWhenFilterAddedThenBehaviorMatchesNamespace() {
		this.spring.register(CustomFilterPositionConfig.class, UserDetailsServiceConfig.class).autowire();
		assertThatFilters().containsExactly(CustomFilter.class);
	}

	@Test
	public void getFiltersWhenFilterAddedAtPositionThenBehaviorMatchesNamespace() {
		this.spring.register(CustomFilterPositionAtConfig.class, UserDetailsServiceConfig.class).autowire();
		assertThatFilters().containsExactly(OtherCustomFilter.class);
	}

	@Test
	public void getFiltersWhenCustomAuthenticationManagerThenBehaviorMatchesNamespace() {
		this.spring.register(NoAuthenticationManagerInHttpConfigurationConfig.class).autowire();
		assertThatFilters().startsWith(CustomFilter.class);
	}

	private ListAssert<Class<?>> assertThatFilters() {
		FilterChainProxy filterChain = this.spring.getContext().getBean(FilterChainProxy.class);
		List<Class<?>> filters = filterChain.getFilters("/").stream().map(Object::getClass)
				.collect(Collectors.toList());
		return assertThat(filters);
	}

	@Configuration
	@EnableWebSecurity
	static class CustomFilterBeforeConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.addFilterBefore(new CustomFilter(), UsernamePasswordAuthenticationFilter.class)
				.formLogin();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomFilterAfterConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.addFilterAfter(new CustomFilter(), UsernamePasswordAuthenticationFilter.class)
				.formLogin();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomFilterPositionConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			TestHttpSecurity.disableDefaults(http);
			http
				// this works so long as the CustomFilter extends one of the standard filters
				// if not, use addFilterBefore or addFilterAfter
				.addFilter(new CustomFilter());
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomFilterPositionAtConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			TestHttpSecurity.disableDefaults(http);
			http
				.addFilterAt(new OtherCustomFilter(), UsernamePasswordAuthenticationFilter.class);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class NoAuthenticationManagerInHttpConfigurationConfig {

		@Bean
		AuthenticationManager authenticationManager() {
			return new CustomAuthenticationManager();
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			TestHttpSecurity.disableDefaults(http);
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.addFilterBefore(new CustomFilter(), UsernamePasswordAuthenticationFilter.class);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	static class UserDetailsServiceConfig {

		@Bean
		UserDetailsService userDetailsService() {
			// @formatter:off
			UserDetails user = User.withDefaultPasswordEncoder()
					.username("user")
					.password("password")
					.roles("USER")
					.build();
			// @formatter:on
			return new InMemoryUserDetailsManager(user);
		}

	}

	static class CustomFilter extends UsernamePasswordAuthenticationFilter {

	}

	static class OtherCustomFilter extends OncePerRequestFilter {

		@Override
		protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
				FilterChain filterChain) throws ServletException, IOException {
			filterChain.doFilter(request, response);
		}

	}

	static class CustomAuthenticationManager implements AuthenticationManager {

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			return null;
		}

	}

}
