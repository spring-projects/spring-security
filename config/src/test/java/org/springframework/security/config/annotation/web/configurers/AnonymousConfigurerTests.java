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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.config.annotation.SecurityContextChangedListenerConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextChangedListener;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.annotation.SecurityContextChangedListenerArgumentMatchers.setAuthentication;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rob Winch
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension.class)
public class AnonymousConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void requestWhenAnonymousTwiceInvokedThenDoesNotOverride() throws Exception {
		this.spring.register(InvokeTwiceDoesNotOverride.class, PrincipalController.class).autowire();
		this.mockMvc.perform(get("/")).andExpect(content().string("principal"));
	}

	@Test
	public void requestWhenAnonymousPrincipalInLambdaThenPrincipalUsed() throws Exception {
		this.spring.register(AnonymousPrincipalInLambdaConfig.class, PrincipalController.class).autowire();
		this.mockMvc.perform(get("/")).andExpect(content().string("principal"));
	}

	@Test
	public void requestWhenCustomSecurityContextHolderStrategyThenUses() throws Exception {
		this.spring.register(AnonymousPrincipalInLambdaConfig.class, SecurityContextChangedListenerConfig.class,
				PrincipalController.class).autowire();
		this.mockMvc.perform(get("/")).andExpect(content().string("principal"));
		SecurityContextChangedListener listener = this.spring.getContext()
				.getBean(SecurityContextChangedListener.class);
		verify(listener).securityContextChanged(setAuthentication(AnonymousAuthenticationToken.class));
	}

	@Test
	public void requestWhenAnonymousDisabledInLambdaThenRespondsWithForbidden() throws Exception {
		this.spring.register(AnonymousDisabledInLambdaConfig.class, PrincipalController.class).autowire();
		this.mockMvc.perform(get("/")).andExpect(status().isForbidden());
	}

	@Test
	public void requestWhenAnonymousWithDefaultsInLambdaThenRespondsWithOk() throws Exception {
		this.spring.register(AnonymousWithDefaultsInLambdaConfig.class, PrincipalController.class).autowire();
		this.mockMvc.perform(get("/")).andExpect(status().isOk());
	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class InvokeTwiceDoesNotOverride {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.anonymous()
					.key("key")
					.principal("principal")
					.and()
				.anonymous();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class AnonymousPrincipalInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.anonymous((anonymous) ->
					anonymous
						.principal("principal")
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AnonymousDisabledInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().permitAll()
				)
				.anonymous(AbstractHttpConfigurer::disable);
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class AnonymousWithDefaultsInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().permitAll()
				)
				.anonymous(withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@RestController
	static class PrincipalController {

		@GetMapping("/")
		String principal(@AuthenticationPrincipal String principal) {
			return principal;
		}

	}

}
