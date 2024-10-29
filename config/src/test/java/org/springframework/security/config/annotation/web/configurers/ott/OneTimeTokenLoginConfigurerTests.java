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

package org.springframework.security.config.annotation.web.configurers.ott;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatException;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringTestContextExtension.class)
public class OneTimeTokenLoginConfigurerTests {

	public SpringTestContext spring = new SpringTestContext(this);

	@Autowired(required = false)
	MockMvc mvc;

	@Test
	void oneTimeTokenWhenCorrectTokenThenCanAuthenticate() throws Exception {
		this.spring.register(OneTimeTokenDefaultConfig.class).autowire();
		this.mvc.perform(post("/ott/generate").param("username", "user").with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/login/ott"));

		String token = TestOneTimeTokenGenerationSuccessHandler.lastToken.getTokenValue();

		this.mvc.perform(post("/login/ott").param("token", token).with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/"), authenticated());
	}

	@Test
	void oneTimeTokenWhenDifferentAuthenticationUrlsThenCanAuthenticate() throws Exception {
		this.spring.register(OneTimeTokenDifferentUrlsConfig.class).autowire();
		this.mvc.perform(post("/generateurl").param("username", "user").with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/redirected"));

		String token = TestOneTimeTokenGenerationSuccessHandler.lastToken.getTokenValue();

		this.mvc.perform(post("/loginprocessingurl").param("token", token).with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/authenticated"), authenticated());
	}

	@Test
	void oneTimeTokenWhenCorrectTokenUsedTwiceThenSecondTimeFails() throws Exception {
		this.spring.register(OneTimeTokenDefaultConfig.class).autowire();
		this.mvc.perform(post("/ott/generate").param("username", "user").with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/login/ott"));

		String token = TestOneTimeTokenGenerationSuccessHandler.lastToken.getTokenValue();

		this.mvc.perform(post("/login/ott").param("token", token).with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/"), authenticated());

		this.mvc.perform(post("/login/ott").param("token", token).with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/login?error"), unauthenticated());
	}

	@Test
	void oneTimeTokenWhenWrongTokenThenAuthenticationFail() throws Exception {
		this.spring.register(OneTimeTokenDefaultConfig.class).autowire();
		this.mvc.perform(post("/ott/generate").param("username", "user").with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/login/ott"));

		String token = "wrong";

		this.mvc.perform(post("/login/ott").param("token", token).with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/login?error"), unauthenticated());
	}

	@Test
	void oneTimeTokenWhenConfiguredThenServesCss() throws Exception {
		this.spring.register(OneTimeTokenDefaultConfig.class).autowire();
		this.mvc.perform(get("/default-ui.css"))
			.andExpect(status().isOk())
			.andExpect(content().string(Matchers.containsString("body {")));
	}

	@Test
	void oneTimeTokenWhenFormLoginConfiguredThenRendersRequestTokenForm() throws Exception {
		this.spring.register(OneTimeTokenFormLoginConfig.class).autowire();
		CsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "BaseSpringSpec_CSRFTOKEN");
		String csrfAttributeName = HttpSessionCsrfTokenRepository.class.getName().concat(".CSRF_TOKEN");
		//@formatter:off
		this.mvc.perform(get("/login").sessionAttr(csrfAttributeName, csrfToken))
				.andExpect((result) -> {
					CsrfToken token = (CsrfToken) result.getRequest().getAttribute(CsrfToken.class.getName());
					assertThat(result.getResponse().getContentAsString()).isEqualTo(
						"""
						<!DOCTYPE html>
						<html lang="en">
						  <head>
						    <meta charset="utf-8">
						    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
						    <meta name="description" content="">
						    <meta name="author" content="">
						    <title>Please sign in</title>
						    <link href="/default-ui.css" rel="stylesheet" />
						  </head>
						  <body>
						    <div class="content">
						      <form class="login-form" method="post" action="/login">
						        <h2>Please sign in</h2>

						        <p>
						          <label for="username" class="screenreader">Username</label>
						          <input type="text" id="username" name="username" placeholder="Username" required autofocus>
						        </p>
						        <p>
						          <label for="password" class="screenreader">Password</label>
						          <input type="password" id="password" name="password" placeholder="Password" required>
						        </p>

						<input name="_csrf" type="hidden" value="%s" />
						        <button type="submit" class="primary">Sign in</button>
						      </form>
						      <form id="ott-form" class="login-form" method="post" action="/ott/generate">
						        <h2>Request a One-Time Token</h2>

						        <p>
						          <label for="ott-username" class="screenreader">Username</label>
						          <input type="text" id="ott-username" name="username" placeholder="Username" required>
						        </p>
						<input name="_csrf" type="hidden" value="%s" />
						        <button class="primary" type="submit" form="ott-form">Send Token</button>
						      </form>


						    </div>
						  </body>
						</html>""".formatted(token.getToken(), token.getToken()));
				});
		//@formatter:on
	}

	@Test
	void oneTimeTokenWhenNoTokenGenerationSuccessHandlerThenException() {
		assertThatException()
			.isThrownBy(() -> this.spring.register(OneTimeTokenNoGeneratedOttHandlerConfig.class).autowire())
			.havingRootCause()
			.isInstanceOf(IllegalStateException.class)
			.withMessage("""
					A OneTimeTokenGenerationSuccessHandler is required to enable oneTimeTokenLogin().
					Please provide it as a bean or pass it to the oneTimeTokenLogin() DSL.
					""");
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
					.oneTimeTokenLogin((ott) -> ott
							.tokenGenerationSuccessHandler(new TestOneTimeTokenGenerationSuccessHandler())
					);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebSecurity
	@Import(UserDetailsServiceConfig.class)
	static class OneTimeTokenDifferentUrlsConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeHttpRequests((authz) -> authz
							.anyRequest().authenticated()
					)
					.oneTimeTokenLogin((ott) -> ott
							.tokenGeneratingUrl("/generateurl")
							.tokenGenerationSuccessHandler(new TestOneTimeTokenGenerationSuccessHandler("/redirected"))
							.loginProcessingUrl("/loginprocessingurl")
							.authenticationSuccessHandler(new SimpleUrlAuthenticationSuccessHandler("/authenticated"))
					);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebSecurity
	@Import(UserDetailsServiceConfig.class)
	static class OneTimeTokenFormLoginConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeHttpRequests((authz) -> authz
							.anyRequest().authenticated()
					)
					.formLogin(Customizer.withDefaults())
					.oneTimeTokenLogin((ott) -> ott
							.tokenGenerationSuccessHandler(new TestOneTimeTokenGenerationSuccessHandler())
					);
			// @formatter:on
			return http.build();
		}

	}

	@Configuration(proxyBeanMethods = false)
	@EnableWebSecurity
	@Import(UserDetailsServiceConfig.class)
	static class OneTimeTokenNoGeneratedOttHandlerConfig {

		@Bean
		SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeHttpRequests((authz) -> authz
							.anyRequest().authenticated()
					)
					.oneTimeTokenLogin(Customizer.withDefaults());
			// @formatter:on
			return http.build();
		}

	}

	static class TestOneTimeTokenGenerationSuccessHandler implements OneTimeTokenGenerationSuccessHandler {

		private static OneTimeToken lastToken;

		private final OneTimeTokenGenerationSuccessHandler delegate;

		TestOneTimeTokenGenerationSuccessHandler() {
			this.delegate = new RedirectOneTimeTokenGenerationSuccessHandler("/login/ott");
		}

		TestOneTimeTokenGenerationSuccessHandler(String redirectUrl) {
			this.delegate = new RedirectOneTimeTokenGenerationSuccessHandler(redirectUrl);
		}

		@Override
		public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken oneTimeToken)
				throws IOException, ServletException {
			lastToken = oneTimeToken;
			this.delegate.handle(request, response, oneTimeToken);
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
