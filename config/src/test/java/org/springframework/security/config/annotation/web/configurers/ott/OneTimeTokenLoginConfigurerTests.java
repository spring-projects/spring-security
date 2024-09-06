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
import org.springframework.security.web.authentication.ott.GeneratedOneTimeTokenHandler;
import org.springframework.security.web.authentication.ott.RedirectGeneratedOneTimeTokenHandler;
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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringTestContextExtension.class)
public class OneTimeTokenLoginConfigurerTests {

	public SpringTestContext spring = new SpringTestContext(this);

	@Autowired(required = false)
	MockMvc mvc;

	public static final String EXPECTED_HTML_HEAD = """
			<!DOCTYPE html>
			<html lang="en">
			  <head>
			    <meta charset="utf-8">
			    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
			    <meta name="description" content="">
			    <meta name="author" content="">
			    <title>Please sign in</title>
			    <style>
			    /* General layout */
			    body {
			      font-family: system-ui, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
			      background-color: #eee;
			      padding: 40px 0;
			      margin: 0;
			      line-height: 1.5;
			    }
			\s\s\s\s
			    h2 {
			      margin-top: 0;
			      margin-bottom: 0.5rem;
			      font-size: 2rem;
			      font-weight: 500;
			      line-height: 2rem;
			    }
			\s\s\s\s
			    .content {
			      margin-right: auto;
			      margin-left: auto;
			      padding-right: 15px;
			      padding-left: 15px;
			      width: 100%;
			      box-sizing: border-box;
			    }
			\s\s\s\s
			    @media (min-width: 800px) {
			      .content {
			        max-width: 760px;
			      }
			    }
			\s\s\s\s
			    /* Components */
			    a,
			    a:visited {
			      text-decoration: none;
			      color: #06f;
			    }
			\s\s\s\s
			    a:hover {
			      text-decoration: underline;
			      color: #003c97;
			    }
			\s\s\s\s
			    input[type="text"],
			    input[type="password"] {
			      height: auto;
			      width: 100%;
			      font-size: 1rem;
			      padding: 0.5rem;
			      box-sizing: border-box;
			    }
			\s\s\s\s
			    button {
			      padding: 0.5rem 1rem;
			      font-size: 1.25rem;
			      line-height: 1.5;
			      border: none;
			      border-radius: 0.1rem;
			      width: 100%;
			    }
			\s\s\s\s
			    button.primary {
			      color: #fff;
			      background-color: #06f;
			    }
			\s\s\s\s
			    .alert {
			      padding: 0.75rem 1rem;
			      margin-bottom: 1rem;
			      line-height: 1.5;
			      border-radius: 0.1rem;
			      width: 100%;
			      box-sizing: border-box;
			      border-width: 1px;
			      border-style: solid;
			    }
			\s\s\s\s
			    .alert.alert-danger {
			      color: #6b1922;
			      background-color: #f7d5d7;
			      border-color: #eab6bb;
			    }
			\s\s\s\s
			    .alert.alert-success {
			      color: #145222;
			      background-color: #d1f0d9;
			      border-color: #c2ebcb;
			    }
			\s\s\s\s
			    .screenreader {
			      position: absolute;
			      clip: rect(0 0 0 0);
			      height: 1px;
			      width: 1px;
			      padding: 0;
			      border: 0;
			      overflow: hidden;
			    }
			\s\s\s\s
			    table {
			      width: 100%;
			      max-width: 100%;
			      margin-bottom: 2rem;
			    }
			\s\s\s\s
			    .table-striped tr:nth-of-type(2n + 1) {
			      background-color: #e1e1e1;
			    }
			\s\s\s\s
			    td {
			      padding: 0.75rem;
			      vertical-align: top;
			    }
			\s\s\s\s
			    /* Login / logout layouts */
			    .login-form,
			    .logout-form {
			      max-width: 340px;
			      padding: 0 15px 15px 15px;
			      margin: 0 auto 2rem auto;
			      box-sizing: border-box;
			    }
			    </style>
			  </head>
			""";

	@Test
	void oneTimeTokenWhenCorrectTokenThenCanAuthenticate() throws Exception {
		this.spring.register(OneTimeTokenDefaultConfig.class).autowire();
		this.mvc.perform(post("/ott/generate").param("username", "user").with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/login/ott"));

		String token = TestGeneratedOneTimeTokenHandler.lastToken.getTokenValue();

		this.mvc.perform(post("/login/ott").param("token", token).with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/"), authenticated());
	}

	@Test
	void oneTimeTokenWhenDifferentAuthenticationUrlsThenCanAuthenticate() throws Exception {
		this.spring.register(OneTimeTokenDifferentUrlsConfig.class).autowire();
		this.mvc.perform(post("/generateurl").param("username", "user").with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/redirected"));

		String token = TestGeneratedOneTimeTokenHandler.lastToken.getTokenValue();

		this.mvc.perform(post("/loginprocessingurl").param("token", token).with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/authenticated"), authenticated());
	}

	@Test
	void oneTimeTokenWhenCorrectTokenUsedTwiceThenSecondTimeFails() throws Exception {
		this.spring.register(OneTimeTokenDefaultConfig.class).autowire();
		this.mvc.perform(post("/ott/generate").param("username", "user").with(csrf()))
			.andExpectAll(status().isFound(), redirectedUrl("/login/ott"));

		String token = TestGeneratedOneTimeTokenHandler.lastToken.getTokenValue();

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
	void oneTimeTokenWhenFormLoginConfiguredThenRendersRequestTokenForm() throws Exception {
		this.spring.register(OneTimeTokenFormLoginConfig.class).autowire();
		CsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "BaseSpringSpec_CSRFTOKEN");
		String csrfAttributeName = HttpSessionCsrfTokenRepository.class.getName().concat(".CSRF_TOKEN");
		//@formatter:off
		this.mvc.perform(get("/login").sessionAttr(csrfAttributeName, csrfToken))
				.andExpect((result) -> {
					CsrfToken token = (CsrfToken) result.getRequest().getAttribute(CsrfToken.class.getName());
					assertThat(result.getResponse().getContentAsString()).isEqualTo(
						EXPECTED_HTML_HEAD +
						"""
						  <body>
						    <div class="content">
						      <form class="login-form" method="post" action="/login">
						        <h2>Please sign in</h2>
						       \s
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
						     \s
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
	void oneTimeTokenWhenNoGeneratedOneTimeTokenHandlerThenException() {
		assertThatException()
			.isThrownBy(() -> this.spring.register(OneTimeTokenNoGeneratedOttHandlerConfig.class).autowire())
			.havingRootCause()
			.isInstanceOf(IllegalStateException.class)
			.withMessage("""
					A GeneratedOneTimeTokenHandler is required to enable oneTimeTokenLogin().
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
							.generatedOneTimeTokenHandler(new TestGeneratedOneTimeTokenHandler())
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
							.generateTokenUrl("/generateurl")
							.generatedOneTimeTokenHandler(new TestGeneratedOneTimeTokenHandler("/redirected"))
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
							.generatedOneTimeTokenHandler(new TestGeneratedOneTimeTokenHandler())
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

	static class TestGeneratedOneTimeTokenHandler implements GeneratedOneTimeTokenHandler {

		private static OneTimeToken lastToken;

		private final GeneratedOneTimeTokenHandler delegate;

		TestGeneratedOneTimeTokenHandler() {
			this.delegate = new RedirectGeneratedOneTimeTokenHandler("/login/ott");
		}

		TestGeneratedOneTimeTokenHandler(String redirectUrl) {
			this.delegate = new RedirectGeneratedOneTimeTokenHandler(redirectUrl);
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
