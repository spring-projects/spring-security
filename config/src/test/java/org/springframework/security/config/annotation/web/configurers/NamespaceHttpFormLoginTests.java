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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

/**
 * Tests to verify that all the functionality of &lt;form-login&gt; attributes is present
 *
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
@ExtendWith(SpringTestContextExtension.class)
public class NamespaceHttpFormLoginTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void formLoginWhenDefaultConfigurationThenMatchesNamespace() throws Exception {
		this.spring.register(FormLoginConfig.class, UserDetailsServiceConfig.class).autowire();
		this.mvc.perform(get("/")).andExpect(redirectedUrl("http://localhost/login"));
		this.mvc.perform(post("/login").with(csrf())).andExpect(redirectedUrl("/login?error"));
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.param("username", "user")
				.param("password", "password")
				.with(csrf());
		// @formatter:on
		this.mvc.perform(loginRequest).andExpect(redirectedUrl("/"));
	}

	@Test
	public void formLoginWithCustomEndpointsThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(FormLoginCustomConfig.class, UserDetailsServiceConfig.class).autowire();
		this.mvc.perform(get("/")).andExpect(redirectedUrl("http://localhost/authentication/login"));
		this.mvc.perform(post("/authentication/login/process").with(csrf()))
			.andExpect(redirectedUrl("/authentication/login?failed"));
		// @formatter:off
		MockHttpServletRequestBuilder request = post("/authentication/login/process")
				.param("username", "user")
				.param("password", "password")
				.with(csrf());
		// @formatter:on
		this.mvc.perform(request).andExpect(redirectedUrl("/default"));
	}

	@Test
	public void formLoginWithCustomHandlersThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(FormLoginCustomRefsConfig.class, UserDetailsServiceConfig.class).autowire();
		this.mvc.perform(get("/")).andExpect(redirectedUrl("http://localhost/login"));
		this.mvc.perform(post("/login").with(csrf())).andExpect(redirectedUrl("/custom/failure"));
		verifyBean(WebAuthenticationDetailsSource.class).buildDetails(any(HttpServletRequest.class));
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.param("username", "user")
				.param("password", "password")
				.with(csrf());
		// @formatter:on
		this.mvc.perform(loginRequest).andExpect(redirectedUrl("/custom/targetUrl"));
	}

	private <T> T verifyBean(Class<T> beanClass) {
		return verify(this.spring.getContext().getBean(beanClass));
	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class FormLoginConfig {

		@Bean
		WebSecurityCustomizer webSecurityCustomizer() {
			return (web) -> web.ignoring().requestMatchers("/resources/**");
		}

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class FormLoginCustomConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			boolean alwaysUseDefaultSuccess = true;
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.usernameParameter("username") // form-login@username-parameter
					.passwordParameter("password") // form-login@password-parameter
					.loginPage("/authentication/login") // form-login@login-page
					.failureUrl("/authentication/login?failed") // form-login@authentication-failure-url
					.loginProcessingUrl("/authentication/login/process") // form-login@login-processing-url
					.defaultSuccessUrl("/default", alwaysUseDefaultSuccess);
			return http.build(); // form-login@default-target-url / form-login@always-use-default-target
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class FormLoginCustomRefsConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
			successHandler.setDefaultTargetUrl("/custom/targetUrl");
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.loginPage("/login")
					.failureHandler(new SimpleUrlAuthenticationFailureHandler("/custom/failure")) // form-login@authentication-failure-handler-ref
					.successHandler(successHandler) // form-login@authentication-success-handler-ref
					.authenticationDetailsSource(authenticationDetailsSource()) // form-login@authentication-details-source-ref
					.and();
			return http.build();
			// @formatter:on
		}

		@Bean
		WebAuthenticationDetailsSource authenticationDetailsSource() {
			return spy(WebAuthenticationDetailsSource.class);
		}

	}

	@Configuration
	static class UserDetailsServiceConfig {

		@Bean
		UserDetailsService userDetailsService() {
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

}
