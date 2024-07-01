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

package org.springframework.security.config.annotation.web.configurers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
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
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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

	//@formatter:off
	public static final String EXPECTED_HTML_HEAD = "  <head>\n"
			+ "    <meta charset=\"utf-8\">\n"
			+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
			+ "    <meta name=\"description\" content=\"\">\n"
			+ "    <meta name=\"author\" content=\"\">\n"
			+ "    <title>Please sign in</title>\n"
			+ "    <style>\n"
			+ "    /* General layout */\n"
			+ "    body {\n"
			+ "      font-family: system-ui, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif;\n"
			+ "      background-color: #eee;\n"
			+ "      padding: 40px 0;\n"
			+ "      margin: 0;\n"
			+ "      line-height: 1.5;\n"
			+ "    }\n"
			+ "    \n"
			+ "    h2 {\n"
			+ "      margin-top: 0;\n"
			+ "      margin-bottom: 0.5rem;\n"
			+ "      font-size: 2rem;\n"
			+ "      font-weight: 500;\n"
			+ "      line-height: 2rem;\n"
			+ "    }\n"
			+ "    \n"
			+ "    .content {\n"
			+ "      margin-right: auto;\n"
			+ "      margin-left: auto;\n"
			+ "      padding-right: 15px;\n"
			+ "      padding-left: 15px;\n"
			+ "      width: 100%;\n"
			+ "      box-sizing: border-box;\n"
			+ "    }\n"
			+ "    \n"
			+ "    @media (min-width: 800px) {\n"
			+ "      .content {\n"
			+ "        max-width: 760px;\n"
			+ "      }\n"
			+ "    }\n"
			+ "    \n"
			+ "    /* Components */\n"
			+ "    a,\n"
			+ "    a:visited {\n"
			+ "      text-decoration: none;\n"
			+ "      color: #06f;\n"
			+ "    }\n"
			+ "    \n"
			+ "    a:hover {\n"
			+ "      text-decoration: underline;\n"
			+ "      color: #003c97;\n"
			+ "    }\n"
			+ "    \n"
			+ "    input[type=\"text\"],\n"
			+ "    input[type=\"password\"] {\n"
			+ "      height: auto;\n"
			+ "      width: 100%;\n"
			+ "      font-size: 1rem;\n"
			+ "      padding: 0.5rem;\n"
			+ "      box-sizing: border-box;\n"
			+ "    }\n"
			+ "    \n"
			+ "    button {\n"
			+ "      padding: 0.5rem 1rem;\n"
			+ "      font-size: 1.25rem;\n"
			+ "      line-height: 1.5;\n"
			+ "      border: none;\n"
			+ "      border-radius: 0.1rem;\n"
			+ "      width: 100%;\n"
			+ "    }\n"
			+ "    \n"
			+ "    button.primary {\n"
			+ "      color: #fff;\n"
			+ "      background-color: #06f;\n"
			+ "    }\n"
			+ "    \n"
			+ "    .alert {\n"
			+ "      padding: 0.75rem 1rem;\n"
			+ "      margin-bottom: 1rem;\n"
			+ "      line-height: 1.5;\n"
			+ "      border-radius: 0.1rem;\n"
			+ "      width: 100%;\n"
			+ "      box-sizing: border-box;\n"
			+ "      border-width: 1px;\n"
			+ "      border-style: solid;\n"
			+ "    }\n"
			+ "    \n"
			+ "    .alert.alert-danger {\n"
			+ "      color: #6b1922;\n"
			+ "      background-color: #f7d5d7;\n"
			+ "      border-color: #eab6bb;\n"
			+ "    }\n"
			+ "    \n"
			+ "    .alert.alert-success {\n"
			+ "      color: #145222;\n"
			+ "      background-color: #d1f0d9;\n"
			+ "      border-color: #c2ebcb;\n"
			+ "    }\n"
			+ "    \n"
			+ "    .screenreader {\n"
			+ "      position: absolute;\n"
			+ "      clip: rect(0 0 0 0);\n"
			+ "      height: 1px;\n"
			+ "      width: 1px;\n"
			+ "      padding: 0;\n"
			+ "      border: 0;\n"
			+ "      overflow: hidden;\n"
			+ "    }\n"
			+ "    \n"
			+ "    table {\n"
			+ "      width: 100%;\n"
			+ "      max-width: 100%;\n"
			+ "      margin-bottom: 2rem;\n"
			+ "    }\n"
			+ "    \n"
			+ "    .table-striped tr:nth-of-type(2n + 1) {\n"
			+ "      background-color: #e1e1e1;\n"
			+ "    }\n"
			+ "    \n"
			+ "    td {\n"
			+ "      padding: 0.75rem;\n"
			+ "      vertical-align: top;\n"
			+ "    }\n"
			+ "    \n"
			+ "    /* Login / logout layouts */\n"
			+ "    .login-form,\n"
			+ "    .logout-form {\n"
			+ "      max-width: 340px;\n"
			+ "      padding: 0 15px 15px 15px;\n"
			+ "      margin: 0 auto 2rem auto;\n"
			+ "      box-sizing: border-box;\n"
			+ "    }\n"
			+ "    </style>\n"
			+ "  </head>\n";
	//@formatter:on

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

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
					assertThat(result.getResponse().getContentAsString()).isEqualTo("<!DOCTYPE html>\n"
						+ "<html lang=\"en\">\n"
						+ EXPECTED_HTML_HEAD
						+ "  <body>\n"
						+ "     <div class=\"content\">\n"
						+ "      <form class=\"login-form\" method=\"post\" action=\"/login\">\n"
						+ "        <h2>Please sign in</h2>\n"
						+ "        <p>\n"
						+ "          <label for=\"username\" class=\"screenreader\">Username</label>\n"
						+ "          <input type=\"text\" id=\"username\" name=\"username\" placeholder=\"Username\" required autofocus>\n"
						+ "        </p>\n"
						+ "        <p>\n"
						+ "          <label for=\"password\" class=\"screenreader\">Password</label>\n"
						+ "          <input type=\"password\" id=\"password\" name=\"password\" placeholder=\"Password\" required>\n"
						+ "        </p>\n"
						+ "<input name=\"" + token.getParameterName() + "\" type=\"hidden\" value=\"" + token.getToken() + "\" />\n"
						+ "        <button type=\"submit\" class=\"primary\">Sign in</button>\n"
						+ "      </form>\n"
						+ "</div>\n"
						+ "</body></html>");
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
					CsrfToken token = (CsrfToken) result.getRequest().getAttribute(CsrfToken.class.getName());
					assertThat(result.getResponse().getContentAsString()).isEqualTo("<!DOCTYPE html>\n"
						+ "<html lang=\"en\">\n"
						+ EXPECTED_HTML_HEAD
						+ "  <body>\n"
						+ "     <div class=\"content\">\n"
						+ "      <form class=\"login-form\" method=\"post\" action=\"/login\">\n"
						+ "        <h2>Please sign in</h2>\n"
						+ "<div class=\"alert alert-danger\" role=\"alert\">Bad credentials</div>        <p>\n"
						+ "          <label for=\"username\" class=\"screenreader\">Username</label>\n"
						+ "          <input type=\"text\" id=\"username\" name=\"username\" placeholder=\"Username\" required autofocus>\n"
						+ "        </p>\n" + "        <p>\n"
						+ "          <label for=\"password\" class=\"screenreader\">Password</label>\n"
						+ "          <input type=\"password\" id=\"password\" name=\"password\" placeholder=\"Password\" required>\n"
						+ "        </p>\n"
						+ "<input name=\"" + token.getParameterName() + "\" type=\"hidden\" value=\"" + token.getToken() + "\" />\n"
						+ "        <button type=\"submit\" class=\"primary\">Sign in</button>\n"
						+ "      </form>\n"
						+ "</div>\n"
						+ "</body></html>");
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
					assertThat(result.getResponse().getContentAsString()).isEqualTo("<!DOCTYPE html>\n"
						+ "<html lang=\"en\">\n"
						+ EXPECTED_HTML_HEAD
						+ "  <body>\n"
						+ "     <div class=\"content\">\n"
						+ "      <form class=\"login-form\" method=\"post\" action=\"/login\">\n"
						+ "        <h2>Please sign in</h2>\n"
						+ "<div class=\"alert alert-success\" role=\"alert\">You have been signed out</div>        <p>\n"
						+ "          <label for=\"username\" class=\"screenreader\">Username</label>\n"
						+ "          <input type=\"text\" id=\"username\" name=\"username\" placeholder=\"Username\" required autofocus>\n"
						+ "        </p>\n"
						+ "        <p>\n"
						+ "          <label for=\"password\" class=\"screenreader\">Password</label>\n"
						+ "          <input type=\"password\" id=\"password\" name=\"password\" placeholder=\"Password\" required>\n"
						+ "        </p>\n"
						+ "<input name=\"" + token.getParameterName() + "\" type=\"hidden\" value=\"" + token.getToken() + "\" />\n"
						+ "        <button type=\"submit\" class=\"primary\">Sign in</button>\n"
						+ "      </form>\n"
						+ "</div>\n"
						+ "</body></html>");
				});
		// @formatter:on
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
					assertThat(result.getResponse().getContentAsString()).isEqualTo("<!DOCTYPE html>\n"
						+ "<html lang=\"en\">\n"
						+ EXPECTED_HTML_HEAD
						+ "  <body>\n"
						+ "     <div class=\"content\">\n"
						+ "      <form class=\"login-form\" method=\"post\" action=\"/login\">\n"
						+ "        <h2>Please sign in</h2>\n"
						+ "        <p>\n"
						+ "          <label for=\"username\" class=\"screenreader\">Username</label>\n"
						+ "          <input type=\"text\" id=\"username\" name=\"username\" placeholder=\"Username\" required autofocus>\n"
						+ "        </p>\n"
						+ "        <p>\n"
						+ "          <label for=\"password\" class=\"screenreader\">Password</label>\n"
						+ "          <input type=\"password\" id=\"password\" name=\"password\" placeholder=\"Password\" required>\n"
						+ "        </p>\n"
						+ "<p><input type='checkbox' name='remember-me'/> Remember me on this computer.</p>\n"
						+ "<input name=\"" + token.getParameterName() + "\" type=\"hidden\" value=\"" + token.getToken() + "\" />\n"
						+ "        <button type=\"submit\" class=\"primary\">Sign in</button>\n"
						+ "      </form>\n"
						+ "</div>\n"
						+ "</body></html>");
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
