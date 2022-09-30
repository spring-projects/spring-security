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

import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;

import jakarta.servlet.http.HttpSession;
import org.assertj.core.api.Condition;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests to verify that all the functionality of &lt;logout&gt; attributes is present
 *
 * @author Rob Winch
 * @author Josh Cummings
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@SecurityTestExecutionListeners
public class NamespaceHttpLogoutTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	/**
	 * http/logout equivalent
	 */
	@Test
	@WithMockUser
	public void logoutWhenUsingDefaultsThenMatchesNamespace() throws Exception {
		this.spring.register(HttpLogoutConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(post("/logout").with(csrf()))
				.andExpect(authenticated(false))
				.andExpect(redirectedUrl("/login?logout"))
				.andExpect(noCookies())
				.andExpect(session(Objects::isNull));
		// @formatter:on
	}

	@Test
	@WithMockUser
	public void logoutWhenDisabledInLambdaThenRespondsWithNotFound() throws Exception {
		this.spring.register(HttpLogoutDisabledInLambdaConfig.class).autowire();
		MockHttpServletRequestBuilder logoutRequest = post("/logout").with(csrf()).with(user("user"));
		this.mvc.perform(logoutRequest).andExpect(status().isNotFound());
	}

	/**
	 * http/logout custom
	 */
	@Test
	@WithMockUser
	public void logoutWhenUsingVariousCustomizationsMatchesNamespace() throws Exception {
		this.spring.register(CustomHttpLogoutConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(post("/custom-logout").with(csrf()))
				.andExpect(authenticated(false))
				.andExpect(redirectedUrl("/logout-success"))
				.andExpect((result) -> assertThat(result.getResponse().getCookies()).hasSize(1))
				.andExpect(cookie().maxAge("remove", 0))
				.andExpect(session(Objects::nonNull));
		// @formatter:on
	}

	@Test
	@WithMockUser
	public void logoutWhenUsingVariousCustomizationsInLambdaThenMatchesNamespace() throws Exception {
		this.spring.register(CustomHttpLogoutInLambdaConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(post("/custom-logout").with(csrf()))
				.andExpect(authenticated(false))
				.andExpect(redirectedUrl("/logout-success"))
				.andExpect((result) -> assertThat(result.getResponse().getCookies()).hasSize(1))
				.andExpect(cookie().maxAge("remove", 0))
				.andExpect(session(Objects::nonNull));
		// @formatter:on
	}

	/**
	 * http/logout@success-handler-ref
	 */
	@Test
	@WithMockUser
	public void logoutWhenUsingSuccessHandlerRefThenMatchesNamespace() throws Exception {
		this.spring.register(SuccessHandlerRefHttpLogoutConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(post("/logout").with(csrf()))
				.andExpect(authenticated(false))
				.andExpect(redirectedUrl("/SuccessHandlerRefHttpLogoutConfig"))
				.andExpect(noCookies())
				.andExpect(session(Objects::isNull));
		// @formatter:on
	}

	@Test
	@WithMockUser
	public void logoutWhenUsingSuccessHandlerRefInLambdaThenMatchesNamespace() throws Exception {
		this.spring.register(SuccessHandlerRefHttpLogoutInLambdaConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(post("/logout").with(csrf()))
				.andExpect(authenticated(false))
				.andExpect(redirectedUrl("/SuccessHandlerRefHttpLogoutConfig"))
				.andExpect(noCookies())
				.andExpect(session(Objects::isNull));
		// @formatter:on
	}

	ResultMatcher authenticated(boolean authenticated) {
		return (result) -> assertThat(Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
				.map(Authentication::isAuthenticated).orElse(false)).isEqualTo(authenticated);
	}

	ResultMatcher noCookies() {
		return (result) -> assertThat(result.getResponse().getCookies()).isEmpty();
	}

	ResultMatcher session(Predicate<HttpSession> sessionPredicate) {
		return (result) -> assertThat(result.getRequest().getSession(false))
				.is(new Condition<>(sessionPredicate, "sessionPredicate failed"));
	}

	@Configuration
	@EnableWebSecurity
	static class HttpLogoutConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HttpLogoutDisabledInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			http.logout(AbstractHttpConfigurer::disable);
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomHttpLogoutConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.logout()
					.deleteCookies("remove") // logout@delete-cookies
					.invalidateHttpSession(false) // logout@invalidate-session=false (default is true)
					.logoutUrl("/custom-logout") // logout@logout-url (default is /logout)
					.logoutSuccessUrl("/logout-success");
			return http.build(); // logout@success-url (default is /login?logout)
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomHttpLogoutInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.logout((logout) ->
						logout.deleteCookies("remove")
							.invalidateHttpSession(false)
							.logoutUrl("/custom-logout")
							.logoutSuccessUrl("/logout-success")
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class SuccessHandlerRefHttpLogoutConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
			logoutSuccessHandler.setDefaultTargetUrl("/SuccessHandlerRefHttpLogoutConfig");
			// @formatter:off
			http
				.logout()
					.logoutSuccessHandler(logoutSuccessHandler);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class SuccessHandlerRefHttpLogoutInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			SimpleUrlLogoutSuccessHandler logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler();
			logoutSuccessHandler.setDefaultTargetUrl("/SuccessHandlerRefHttpLogoutConfig");
			// @formatter:off
			http
				.logout((logout) -> logout.logoutSuccessHandler(logoutSuccessHandler));
			return http.build();
			// @formatter:on
		}

	}

}
