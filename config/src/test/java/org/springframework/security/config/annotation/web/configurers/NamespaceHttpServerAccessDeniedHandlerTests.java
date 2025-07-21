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
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests to verify that all the functionality of &lt;access-denied-handler&gt; attributes
 * is present
 *
 * @author Rob Winch
 * @author Josh Cummings
 *
 */
@ExtendWith(SpringTestContextExtension.class)
public class NamespaceHttpServerAccessDeniedHandlerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void requestWhenCustomAccessDeniedPageThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(AccessDeniedPageConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(get("/").with(authentication(user())))
				.andExpect(status().isForbidden())
				.andExpect(forwardedUrl("/AccessDeniedPageConfig"));
		// @formatter:on
	}

	@Test
	public void requestWhenCustomAccessDeniedPageInLambdaThenForwardedToCustomPage() throws Exception {
		this.spring.register(AccessDeniedPageInLambdaConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(get("/").with(authentication(user())))
				.andExpect(status().isForbidden())
				.andExpect(forwardedUrl("/AccessDeniedPageConfig"));
		// @formatter:on
	}

	@Test
	public void requestWhenCustomAccessDeniedHandlerThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(AccessDeniedHandlerRefConfig.class).autowire();
		this.mvc.perform(get("/").with(authentication(user())));
		verifyBean(AccessDeniedHandler.class).handle(any(HttpServletRequest.class), any(HttpServletResponse.class),
				any(AccessDeniedException.class));
	}

	@Test
	public void requestWhenCustomAccessDeniedHandlerInLambdaThenBehaviorMatchesNamespace() throws Exception {
		this.spring.register(AccessDeniedHandlerRefInLambdaConfig.class).autowire();
		this.mvc.perform(get("/").with(authentication(user())));
		verify(AccessDeniedHandlerRefInLambdaConfig.accessDeniedHandler).handle(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(AccessDeniedException.class));
	}

	private static Authentication user() {
		return UsernamePasswordAuthenticationToken.authenticated("user", null, AuthorityUtils.NO_AUTHORITIES);
	}

	private <T> T verifyBean(Class<T> beanClass) {
		return verify(this.spring.getContext().getBean(beanClass));
	}

	@Configuration
	@EnableWebSecurity
	static class AccessDeniedPageConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.anyRequest().denyAll())
				.exceptionHandling((handling) -> handling
					.accessDeniedPage("/AccessDeniedPageConfig"));
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AccessDeniedPageInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) -> authorize
						.anyRequest().denyAll()
				)
				.exceptionHandling((exceptionHandling) -> exceptionHandling.accessDeniedPage("/AccessDeniedPageConfig")
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AccessDeniedHandlerRefConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
					.anyRequest().denyAll())
				.exceptionHandling((handling) -> handling
					.accessDeniedHandler(accessDeniedHandler()));
			return http.build();
			// @formatter:on
		}

		@Bean
		AccessDeniedHandler accessDeniedHandler() {
			return mock(AccessDeniedHandler.class);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AccessDeniedHandlerRefInLambdaConfig {

		static AccessDeniedHandler accessDeniedHandler = mock(AccessDeniedHandler.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) -> authorize
						.anyRequest().denyAll()
				)
				.exceptionHandling((exceptionHandling) -> exceptionHandling.accessDeniedHandler(accessDeniedHandler())
				);
			return http.build();
			// @formatter:on
		}

		@Bean
		AccessDeniedHandler accessDeniedHandler() {
			return accessDeniedHandler;
		}

	}

}
