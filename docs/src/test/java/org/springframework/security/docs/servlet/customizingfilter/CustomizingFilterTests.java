/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.docs.servlet.customizingfilter;

import java.io.IOException;
import java.util.List;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;

/**
 * Tests for customizing security filters.
 *
 */
@ExtendWith(SpringTestContextExtension.class)
public class CustomizingFilterTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Autowired
	FilterChainProxy filterChainProxy;

	@Test
	public void filterChainWhenBasicDefaultThenBasicAuthenticationFilterPresent() {
		this.spring.register(SecurityConfigBasicDefault.class).autowire();
		List<Filter> filters = this.filterChainProxy.getFilters("/");
		assertThat(filters).extracting("class").contains(BasicAuthenticationFilter.class);
	}

	@Test
	public void filterChainWhenCustomFilterThenCustomFilterPresent() {
		this.spring.register(SecurityConfigCustom.class).autowire();
		List<Filter> filters = this.filterChainProxy.getFilters("/");
		assertThat(filters).extracting("class").contains(SecurityConfigCustom.MyBasicAuthenticationFilter.class);
		assertThat(filters).extracting("class").doesNotContain(BasicAuthenticationFilter.class);
	}

	@Test
	public void requestWhenDisableThenNoWwwAuthenticateHeader() throws Exception {
		this.spring.register(SecurityConfigDisable.class).autowire();
		this.mvc.perform(get("/")).andExpect(header().doesNotExist(HttpHeaders.WWW_AUTHENTICATE));
	}

	@Test
	public void filterChainWhenIncorrectThenBothFiltersPresent() {
		this.spring.register(SecurityConfigIncorrect.class).autowire();
		List<Filter> filters = this.filterChainProxy.getFilters("/");
		assertThat(filters).extracting("class").contains(BasicAuthenticationFilter.class);
		assertThat(filters).extracting("class").contains(SecurityConfigIncorrect.MyBasicAuthenticationFilter.class);
	}

	@Configuration
	@EnableWebSecurity
	static class SecurityConfigBasicDefault {

		// tag::basic-default[]
		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			http
				.httpBasic(Customizer.withDefaults());
			// ...

			return http.build();
		}
		// end::basic-default[]

	}

	@Configuration
	@EnableWebSecurity
	static class SecurityConfigCustom {

		// tag::custom-filter[]
		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			MyBasicAuthenticationFilter basic = new MyBasicAuthenticationFilter();
			// ... configure

			http
				// ...
				.addFilterAt(basic, BasicAuthenticationFilter.class);

			return http.build();
		}
		// end::custom-filter[]

		static class MyBasicAuthenticationFilter implements Filter {

			@Override
			public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
					throws IOException, ServletException {
				chain.doFilter(request, response);
			}

		}

	}

	@Configuration
	@EnableWebSecurity
	static class SecurityConfigDisable {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			http
				// tag::disable[]
				.httpBasic((basic) -> basic.disable());
				// end::disable[]
				// ...

			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class SecurityConfigIncorrect {

		// tag::incorrect[]
		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			MyBasicAuthenticationFilter basic = new MyBasicAuthenticationFilter();
			// ... configure

			http
				.httpBasic(Customizer.withDefaults())
				// ... on no! BasicAuthenticationFilter is added twice!
				.addFilterAt(basic, BasicAuthenticationFilter.class);

			return http.build();
		}
		// end::incorrect[]

		static class MyBasicAuthenticationFilter implements Filter {

			@Override
			public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
					throws IOException, ServletException {
				chain.doFilter(request, response);
			}

		}

	}

	@Configuration
	static class UserDetailsConfig {

		@Bean
		InMemoryUserDetailsManager userDetailsManager() {
			return new InMemoryUserDetailsManager(User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.roles("USER")
				.build());
		}

	}

}
