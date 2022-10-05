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

package org.springframework.security.config.annotation.web.builders;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link HttpSecurity}.
 *
 * @author Rob Winch
 * @author Joe Grandja
 */
@ExtendWith(SpringTestContextExtension.class)
public class HttpConfigurationTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void configureWhenAddFilterUnregisteredThenThrowsBeanCreationException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(UnregisteredFilterConfig.class).autowire())
				.withMessageContaining("The Filter class " + UnregisteredFilter.class.getName()
						+ " does not have a registered order and cannot be added without a specified order."
						+ " Consider using addFilterBefore or addFilterAfter instead.");
	}

	@Test
	public void configureWhenConfigIsRequestMatchersJavadocThenAuthorizationApplied() throws Exception {
		this.spring.register(RequestMatcherRegistryConfigs.class).autowire();
		this.mockMvc.perform(get("/oauth/a")).andExpect(status().isUnauthorized());
		this.mockMvc.perform(get("/oauth/b")).andExpect(status().isUnauthorized());
		this.mockMvc.perform(get("/api/a")).andExpect(status().isUnauthorized());
		this.mockMvc.perform(get("/api/b")).andExpect(status().isUnauthorized());
	}

	@Configuration
	@EnableWebSecurity
	static class UnregisteredFilterConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.addFilter(new UnregisteredFilter());
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	static class UnregisteredFilter extends OncePerRequestFilter {

		@Override
		protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
				FilterChain filterChain) throws ServletException, IOException {
			filterChain.doFilter(request, response);
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class RequestMatcherRegistryConfigs {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.securityMatchers()
					.requestMatchers(new AntPathRequestMatcher("/api/**"))
					.requestMatchers(new AntPathRequestMatcher("/oauth/**"))
					.and()
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.httpBasic();
			return http.build();
			// @formatter:on
		}

	}

}
