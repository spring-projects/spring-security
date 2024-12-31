/*
 * Copyright 2002-2023 the original author or authors.
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
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.authentication.ui.DefaultResourcesFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link DefaultLoginPageConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension.class)
public class DefaultLoginPageConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	@Test
	public void getWhenFormLoginEnabledThenRedirectsToLoginPage() throws Exception {
		this.spring.register(DefaultLoginPageConfig.class).autowire();
		this.mvc.perform(get("/")).andExpect(redirectedUrl("http://localhost/login"));
	}

	@Test
	public void loginPageThenDefaultLoginPageIsRendered() throws Exception {
		this.spring.register(DefaultLoginPageConfig.class).autowire();
		CsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "BaseSpringSpec_CSRFTOKEN");
		String csrfAttributeName = HttpSessionCsrfTokenRepository.class.getName().concat(".CSRF_TOKEN");
		// @formatter:off
		this.mvc.perform(get("/login").sessionAttr(csrfAttributeName, csrfToken))
				.andExpect((result) -> {
					CsrfToken token = (CsrfToken) result.getRequest().getAttribute(CsrfToken.class.getName());
					assertThat(result.getResponse().getContentAsString()).isEqualTo("""
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



						    </div>
						  </body>
						</html>""".formatted(token.getToken()));
				});
		// @formatter:on
	}

	@Test
	public void loginWhenNoCredentialsThenRedirectedToLoginPageWithError() throws Exception {
		this.spring.register(DefaultLoginPageConfig.class).autowire();
		this.mvc.perform(post("/login").with(csrf())).andExpect(redirectedUrl("/login?error"));
	}

	@Test
	public void loginPageWhenErrorThenDefaultLoginPageWithError() throws Exception {
		this.spring.register(DefaultLoginPageConfig.class).autowire();
		CsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "BaseSpringSpec_CSRFTOKEN");
		String csrfAttributeName = HttpSessionCsrfTokenRepository.class.getName().concat(".CSRF_TOKEN");
		MvcResult mvcResult = this.mvc.perform(post("/login").with(csrf())).andReturn();
		// @formatter:off
		this.mvc.perform(get("/login?error").session((MockHttpSession) mvcResult.getRequest().getSession())
				.sessionAttr(csrfAttributeName, csrfToken))
				.andExpect((result) -> {
					String badCredentialsLocalizedMessage = this.messages
							.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials");
					CsrfToken token = (CsrfToken) result.getRequest().getAttribute(CsrfToken.class.getName());
					assertThat(result.getResponse().getContentAsString()).isEqualTo("""
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
						<div class="alert alert-danger" role="alert">%s</div>
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



						    </div>
						  </body>
						</html>""".formatted(badCredentialsLocalizedMessage, token.getToken()));
				});
		// @formatter:on
	}

	@Test
	public void loginWhenValidCredentialsThenRedirectsToDefaultSuccessPage() throws Exception {
		this.spring.register(DefaultLoginPageConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password");
		// @formatter:on
		this.mvc.perform(loginRequest).andExpect(redirectedUrl("/"));
	}

	@Test
	public void loginPageWhenLoggedOutThenDefaultLoginPageWithLogoutMessage() throws Exception {
		this.spring.register(DefaultLoginPageConfig.class).autowire();
		CsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "BaseSpringSpec_CSRFTOKEN");
		String csrfAttributeName = HttpSessionCsrfTokenRepository.class.getName().concat(".CSRF_TOKEN");
		// @formatter:off
		this.mvc.perform(get("/login?logout").sessionAttr(csrfAttributeName, csrfToken))
				.andExpect((result) -> {
					CsrfToken token = (CsrfToken) result.getRequest().getAttribute(CsrfToken.class.getName());
					assertThat(result.getResponse().getContentAsString()).isEqualTo("""
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
						<div class="alert alert-success" role="alert">You have been signed out</div>
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



						    </div>
						  </body>
						</html>""".formatted(token.getToken()));
				});
	}

	@Test
	public void cssWhenFormLoginConfiguredThenServesCss() throws Exception {
		this.spring.register(DefaultLoginPageConfig.class).autowire();
		this.mvc.perform(get("/default-ui.css"))
				.andExpect(status().isOk())
				.andExpect(header().string("content-type", "text/css;charset=UTF-8"))
				.andExpect(content().string(containsString("body {")));
	}

	@Test
	public void loginPageWhenLoggedOutAndCustomLogoutSuccessHandlerThenDoesNotRenderLoginPage() throws Exception {
		this.spring.register(DefaultLoginPageCustomLogoutSuccessHandlerConfig.class).autowire();
		this.mvc.perform(get("/login?logout")).andExpect(content().string(""));
	}

	@Test
	public void loginPageWhenLoggedOutAndCustomLogoutSuccessUrlThenDoesNotRenderLoginPage() throws Exception {
		this.spring.register(DefaultLoginPageCustomLogoutSuccessUrlConfig.class).autowire();
		this.mvc.perform(get("/login?logout")).andExpect(content().string(""));
	}

	@Test
	public void loginPageWhenRememberConfigureThenDefaultLoginPageWithRememberMeCheckbox() throws Exception {
		this.spring.register(DefaultLoginPageWithRememberMeConfig.class).autowire();
		CsrfToken csrfToken = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "BaseSpringSpec_CSRFTOKEN");
		String csrfAttributeName = HttpSessionCsrfTokenRepository.class.getName().concat(".CSRF_TOKEN");
		// @formatter:off
		this.mvc.perform(get("/login").sessionAttr(csrfAttributeName, csrfToken))
				.andExpect((result) -> {
					CsrfToken token = (CsrfToken) result.getRequest().getAttribute(CsrfToken.class.getName());
					assertThat(result.getResponse().getContentAsString()).isEqualTo("""
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
						<p><input type='checkbox' name='remember-me'/> Remember me on this computer.</p>
						<input name="_csrf" type="hidden" value="%s" />
						        <button type="submit" class="primary">Sign in</button>
						      </form>



						    </div>
						  </body>
						</html>""".formatted(token.getToken()));
				});
		// @formatter:on
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnDefaultLoginPageGeneratingFilter() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(DefaultLoginPageGeneratingFilter.class));
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnUsernamePasswordAuthenticationFilter() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor)
			.postProcess(any(UsernamePasswordAuthenticationFilter.class));
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnLoginUrlAuthenticationEntryPoint() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(LoginUrlAuthenticationEntryPoint.class));
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnExceptionTranslationFilter() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(ExceptionTranslationFilter.class));
	}

	@Test
	public void configureWhenAuthenticationEntryPointThenNoDefaultLoginPageGeneratingFilter() {
		this.spring.register(DefaultLoginWithCustomAuthenticationEntryPointConfig.class).autowire();
		FilterChainProxy filterChain = this.spring.getContext().getBean(FilterChainProxy.class);
		assertThat(filterChain.getFilterChains()
			.get(0)
			.getFilters()
			.stream()
			.filter((filter) -> filter.getClass().isAssignableFrom(DefaultLoginPageGeneratingFilter.class))
			.count()).isZero();
	}

	@Test
	public void configureWhenAuthenticationEntryPointThenDoesNotServeCss() throws Exception {
		this.spring.register(DefaultLoginWithCustomAuthenticationEntryPointConfig.class).autowire();
		FilterChainProxy filterChain = this.spring.getContext().getBean(FilterChainProxy.class);
		assertThat(filterChain.getFilterChains()
			.get(0)
			.getFilters()
			.stream()
			.filter((filter) -> filter.getClass().isAssignableFrom(DefaultResourcesFilter.class))
			.count()).isZero();
		//@formatter:off
		this.mvc.perform(get("/default-ui.css"))
				.andExpect(status().is3xxRedirection());
		//@formatter:on
	}

	@Test
	public void formLoginWhenLogoutEnabledThenCreatesDefaultLogoutPage() throws Exception {
		this.spring.register(DefaultLogoutPageConfig.class).autowire();
		this.mvc.perform(get("/logout").with(user("user"))).andExpect(status().isOk());
	}

	@Test
	public void formLoginWhenLogoutDisabledThenDefaultLogoutPageDoesNotExist() throws Exception {
		this.spring.register(LogoutDisabledConfig.class).autowire();
		this.mvc.perform(get("/logout").with(user("user"))).andExpect(status().isNotFound());
	}

	@Configuration
	@EnableWebSecurity
	static class DefaultLoginPageConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin();
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
	static class DefaultLoginPageCustomLogoutSuccessHandlerConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.logout()
					.logoutSuccessHandler(new SimpleUrlLogoutSuccessHandler())
					.and()
				.formLogin();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DefaultLoginPageCustomLogoutSuccessUrlConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.logout()
					.logoutSuccessUrl("/login?logout")
					.and()
				.formLogin();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DefaultLoginPageWithRememberMeConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.and()
				.rememberMe();
			return http.build();
			// @formatter:on
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DefaultLoginWithCustomAuthenticationEntryPointConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.exceptionHandling()
					.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
					.and()
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
	static class ObjectPostProcessorConfig {

		static ObjectPostProcessor<Object> objectPostProcessor;

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.exceptionHandling()
					.and()
				.formLogin();
			return http.build();
			// @formatter:on
		}

		@Bean
		static ObjectPostProcessor<Object> objectPostProcessor() {
			return objectPostProcessor;
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DefaultLogoutPageConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorize) -> authorize
					.anyRequest().authenticated()
				)
				.formLogin(withDefaults());
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class LogoutDisabledConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
					.authorizeRequests((authorize) -> authorize
							.anyRequest().authenticated()
					)
					.formLogin(withDefaults())
					.logout((logout) -> logout
							.disable()
					);
			return http.build();
			// @formatter:on
		}

	}

	static class ReflectingObjectPostProcessor implements ObjectPostProcessor<Object> {

		@Override
		public <O> O postProcess(O object) {
			return object;
		}

	}

}
