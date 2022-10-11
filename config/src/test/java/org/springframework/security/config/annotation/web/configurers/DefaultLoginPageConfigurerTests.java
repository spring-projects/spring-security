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
						+ "  <head>\n"
						+ "    <meta charset=\"utf-8\">\n"
						+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
						+ "    <meta name=\"description\" content=\"\">\n"
						+ "    <meta name=\"author\" content=\"\">\n"
						+ "    <title>Please sign in</title>\n"
						+ "    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n"
						+ "    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n"
						+ "  </head>\n"
						+ "  <body>\n"
						+ "     <div class=\"container\">\n"
						+ "      <form class=\"form-signin\" method=\"post\" action=\"/login\">\n"
						+ "        <h2 class=\"form-signin-heading\">Please sign in</h2>\n"
						+ "        <p>\n"
						+ "          <label for=\"username\" class=\"sr-only\">Username</label>\n"
						+ "          <input type=\"text\" id=\"username\" name=\"username\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
						+ "        </p>\n"
						+ "        <p>\n"
						+ "          <label for=\"password\" class=\"sr-only\">Password</label>\n"
						+ "          <input type=\"password\" id=\"password\" name=\"password\" class=\"form-control\" placeholder=\"Password\" required>\n"
						+ "        </p>\n"
						+ "<input name=\"" + token.getParameterName() + "\" type=\"hidden\" value=\"" + token.getToken() + "\" />\n"
						+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
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
						+ "  <head>\n"
						+ "    <meta charset=\"utf-8\">\n"
						+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
						+ "    <meta name=\"description\" content=\"\">\n"
						+ "    <meta name=\"author\" content=\"\">\n"
						+ "    <title>Please sign in</title>\n"
						+ "    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n"
						+ "    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n"
						+ "  </head>\n"
						+ "  <body>\n"
						+ "     <div class=\"container\">\n"
						+ "      <form class=\"form-signin\" method=\"post\" action=\"/login\">\n"
						+ "        <h2 class=\"form-signin-heading\">Please sign in</h2>\n"
						+ "<div class=\"alert alert-danger\" role=\"alert\">Bad credentials</div>        <p>\n"
						+ "          <label for=\"username\" class=\"sr-only\">Username</label>\n"
						+ "          <input type=\"text\" id=\"username\" name=\"username\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
						+ "        </p>\n" + "        <p>\n"
						+ "          <label for=\"password\" class=\"sr-only\">Password</label>\n"
						+ "          <input type=\"password\" id=\"password\" name=\"password\" class=\"form-control\" placeholder=\"Password\" required>\n"
						+ "        </p>\n"
						+ "<input name=\"" + token.getParameterName() + "\" type=\"hidden\" value=\"" + token.getToken() + "\" />\n"
						+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
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
						+ "  <head>\n"
						+ "    <meta charset=\"utf-8\">\n"
						+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
						+ "    <meta name=\"description\" content=\"\">\n"
						+ "    <meta name=\"author\" content=\"\">\n"
						+ "    <title>Please sign in</title>\n"
						+ "    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n"
						+ "    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n"
						+ "  </head>\n"
						+ "  <body>\n"
						+ "     <div class=\"container\">\n"
						+ "      <form class=\"form-signin\" method=\"post\" action=\"/login\">\n"
						+ "        <h2 class=\"form-signin-heading\">Please sign in</h2>\n"
						+ "<div class=\"alert alert-success\" role=\"alert\">You have been signed out</div>        <p>\n"
						+ "          <label for=\"username\" class=\"sr-only\">Username</label>\n"
						+ "          <input type=\"text\" id=\"username\" name=\"username\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
						+ "        </p>\n"
						+ "        <p>\n"
						+ "          <label for=\"password\" class=\"sr-only\">Password</label>\n"
						+ "          <input type=\"password\" id=\"password\" name=\"password\" class=\"form-control\" placeholder=\"Password\" required>\n"
						+ "        </p>\n"
						+ "<input name=\"" + token.getParameterName() + "\" type=\"hidden\" value=\"" + token.getToken() + "\" />\n"
						+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
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
						+ "  <head>\n"
						+ "    <meta charset=\"utf-8\">\n"
						+ "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">\n"
						+ "    <meta name=\"description\" content=\"\">\n"
						+ "    <meta name=\"author\" content=\"\">\n"
						+ "    <title>Please sign in</title>\n"
						+ "    <link href=\"https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M\" crossorigin=\"anonymous\">\n"
						+ "    <link href=\"https://getbootstrap.com/docs/4.0/examples/signin/signin.css\" rel=\"stylesheet\" crossorigin=\"anonymous\"/>\n"
						+ "  </head>\n"
						+ "  <body>\n"
						+ "     <div class=\"container\">\n"
						+ "      <form class=\"form-signin\" method=\"post\" action=\"/login\">\n"
						+ "        <h2 class=\"form-signin-heading\">Please sign in</h2>\n"
						+ "        <p>\n"
						+ "          <label for=\"username\" class=\"sr-only\">Username</label>\n"
						+ "          <input type=\"text\" id=\"username\" name=\"username\" class=\"form-control\" placeholder=\"Username\" required autofocus>\n"
						+ "        </p>\n"
						+ "        <p>\n"
						+ "          <label for=\"password\" class=\"sr-only\">Password</label>\n"
						+ "          <input type=\"password\" id=\"password\" name=\"password\" class=\"form-control\" placeholder=\"Password\" required>\n"
						+ "        </p>\n"
						+ "<p><input type='checkbox' name='remember-me'/> Remember me on this computer.</p>\n"
						+ "<input name=\"" + token.getParameterName() + "\" type=\"hidden\" value=\"" + token.getToken() + "\" />\n"
						+ "        <button class=\"btn btn-lg btn-primary btn-block\" type=\"submit\">Sign in</button>\n"
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
		assertThat(filterChain.getFilterChains().get(0).getFilters().stream()
				.filter((filter) -> filter.getClass().isAssignableFrom(DefaultLoginPageGeneratingFilter.class)).count())
						.isZero();
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
