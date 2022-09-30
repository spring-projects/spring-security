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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityContextChangedListenerConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextChangedListener;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.annotation.SecurityContextChangedListenerArgumentMatchers.setAuthentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link HttpBasicConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension.class)
public class HttpBasicConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnBasicAuthenticationFilter() {
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(BasicAuthenticationFilter.class));
	}

	@Test
	public void httpBasicWhenUsingDefaultsInLambdaThenResponseIncludesBasicChallenge() throws Exception {
		this.spring.register(DefaultsLambdaEntryPointConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string("WWW-Authenticate", "Basic realm=\"Realm\""));
		// @formatter:on
	}

	// SEC-2198
	@Test
	public void httpBasicWhenUsingDefaultsThenResponseIncludesBasicChallenge() throws Exception {
		this.spring.register(DefaultsEntryPointConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string("WWW-Authenticate", "Basic realm=\"Realm\""));
		// @formatter:on
	}

	@Test
	public void httpBasicWhenUsingCustomAuthenticationEntryPointThenResponseIncludesBasicChallenge() throws Exception {
		this.spring.register(CustomAuthenticationEntryPointConfig.class).autowire();
		this.mvc.perform(get("/"));
		verify(CustomAuthenticationEntryPointConfig.ENTRY_POINT).commence(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(AuthenticationException.class));
	}

	@Test
	public void httpBasicWhenInvokedTwiceThenUsesOriginalEntryPoint() throws Exception {
		this.spring.register(DuplicateDoesNotOverrideConfig.class).autowire();
		this.mvc.perform(get("/"));
		verify(DuplicateDoesNotOverrideConfig.ENTRY_POINT).commence(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(AuthenticationException.class));
	}

	// SEC-3019
	@Test
	public void httpBasicWhenRememberMeConfiguredThenSetsRememberMeCookie() throws Exception {
		this.spring.register(BasicUsesRememberMeConfig.class).autowire();
		MockHttpServletRequestBuilder rememberMeRequest = get("/").with(httpBasic("user", "password"))
				.param("remember-me", "true");
		this.mvc.perform(rememberMeRequest).andExpect(cookie().exists("remember-me"));
	}

	@Test
	public void httpBasicWhenDefaultsThenAcceptsBasicCredentials() throws Exception {
		this.spring.register(HttpBasic.class, Users.class, Home.class).autowire();
		this.mvc.perform(get("/").with(httpBasic("user", "password"))).andExpect(status().isOk())
				.andExpect(content().string("user"));
	}

	@Test
	public void httpBasicWhenCustomSecurityContextHolderStrategyThenUses() throws Exception {
		this.spring.register(HttpBasic.class, Users.class, Home.class, SecurityContextChangedListenerConfig.class)
				.autowire();
		this.mvc.perform(get("/").with(httpBasic("user", "password"))).andExpect(status().isOk())
				.andExpect(content().string("user"));
		SecurityContextChangedListener listener = this.spring.getContext()
				.getBean(SecurityContextChangedListener.class);
		verify(listener).securityContextChanged(setAuthentication(UsernamePasswordAuthenticationToken.class));
	}

	@Configuration
	@EnableWebSecurity
	static class ObjectPostProcessorConfig {

		static ObjectPostProcessor<Object> objectPostProcessor = spy(ReflectingObjectPostProcessor.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic();
			return http.build();
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

	@Configuration
	@EnableWebSecurity
	static class DefaultsLambdaEntryPointConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().authenticated()
				)
				.httpBasic(withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DefaultsEntryPointConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.httpBasic();
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomAuthenticationEntryPointConfig {

		static AuthenticationEntryPoint ENTRY_POINT = mock(AuthenticationEntryPoint.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.httpBasic()
					.authenticationEntryPoint(ENTRY_POINT);
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DuplicateDoesNotOverrideConfig {

		static AuthenticationEntryPoint ENTRY_POINT = mock(AuthenticationEntryPoint.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.httpBasic()
					.authenticationEntryPoint(ENTRY_POINT)
					.and()
				.httpBasic();
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager();
		}

	}

	@EnableWebSecurity
	@Configuration
	static class BasicUsesRememberMeConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.rememberMe();
			return http.build();
			// @formatter:on
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(
			// @formatter:off
					org.springframework.security.core.userdetails.User.withDefaultPasswordEncoder()
							.username("user")
							.password("password")
							.roles("USER")
							.build()
					// @formatter:on
			);
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HttpBasic {

		@Bean
		SecurityFilterChain web(HttpSecurity http) throws Exception {
			http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
					.httpBasic(Customizer.withDefaults());

			return http.build();
		}

	}

	@Configuration
	static class Users {

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

	@EnableWebMvc
	@RestController
	static class Home {

		@GetMapping("/")
		String home(@AuthenticationPrincipal UserDetails user) {
			return user.getUsername();
		}

	}

}
