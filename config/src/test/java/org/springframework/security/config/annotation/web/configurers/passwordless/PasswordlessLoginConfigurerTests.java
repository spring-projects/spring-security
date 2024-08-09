/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.passwordless;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.passwordless.ott.DefaultOneTimeToken;
import org.springframework.security.authentication.passwordless.ott.OneTimeToken;
import org.springframework.security.authentication.passwordless.ott.OneTimeTokenAuthenticationRequest;
import org.springframework.security.authentication.passwordless.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.authentication.passwordless.ott.OneTimeTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThatException;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringTestContextExtension.class)
public class PasswordlessLoginConfigurerTests {

	public SpringTestContext spring = new SpringTestContext(this);

	@Autowired(required = false)
	MockMvc mvc;

	private MockHttpServletRequest request = new MockHttpServletRequest();

	private MockHttpServletResponse response = new MockHttpServletResponse();

	private MockFilterChain filterChain = new MockFilterChain();

	@Test
	void passwordlessLoginWhenNoPasswordlessMethodThenException() {
		assertThatException().isThrownBy(() -> this.spring.register(NoPasswordlessMethodConfig.class).autowire())
			.havingRootCause()
			.isInstanceOf(IllegalStateException.class)
			.withMessage(
					"No authentication converters configured for passwordless login. Please configure at least one passwordless login method");
	}

	@Test
	void oneTimeTokenWhenRightTokenThenCanAuthenticate() throws Exception {
		this.spring.register(OneTimeTokenDefaultConfig.class).autowire();
		this.mvc.perform(post("/ott/authenticate").param("username", "user").with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/login/ott"));

		IncrementalOneTimeTokenService oneTimeTokenService = this.spring.getContext()
			.getBean(IncrementalOneTimeTokenService.class);

		String token = String.valueOf(oneTimeTokenService.counter);

		this.mvc.perform(post("/login/ott").param("token", token).with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/"), authenticated());
	}

	@Test
	void oneTimeTokenWhenWrongTokenThenAuthenticationFail() throws Exception {
		this.spring.register(OneTimeTokenDefaultConfig.class).autowire();
		this.mvc.perform(post("/ott/authenticate").param("username", "user").with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/login/ott"));

		String token = "wrong";

		this.mvc.perform(post("/login/ott").param("token", token).with(csrf()))
			.andExpectAll(status().isUnauthorized(), unauthenticated());
	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebSecurity
	@Import(UserDetailsServiceConfig.class)
	static class OneTimeTokenDefaultConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeHttpRequests((authz) -> authz
							.anyRequest().authenticated()
					)
					.passwordlessLogin((pwless) -> pwless
							.oneTimeToken(Customizer.withDefaults())
					);
			// @formatter:on
			return http.build();
		}

		@Bean
		OneTimeTokenService oneTimeTokenService() {
			return new IncrementalOneTimeTokenService();
		}

	}

	static class IncrementalOneTimeTokenService implements OneTimeTokenService {

		private final Map<String, OneTimeToken> tokens = new ConcurrentHashMap<>();

		int counter = 0;

		@Override
		public OneTimeToken generate(OneTimeTokenAuthenticationRequest request) {
			DefaultOneTimeToken token = new DefaultOneTimeToken(String.valueOf(++this.counter), request.getUsername(),
					Instant.now().plusSeconds(60));
			this.tokens.put(token.getToken(), token);
			return token;
		}

		@Override
		public OneTimeToken consume(OneTimeTokenAuthenticationToken authenticationToken) {
			return this.tokens.remove(authenticationToken.getToken());
		}

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebSecurity
	static class NoPasswordlessMethodConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeHttpRequests((authz) -> authz
							.anyRequest().authenticated()
					)
					.passwordlessLogin(Customizer.withDefaults());
			// @formatter:on
			return http.build();
		}

	}

	@Configuration(proxyBeanMethods = false)
	static class UserDetailsServiceConfig {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user(), PasswordEncodedUser.admin());
		}

	}

}
