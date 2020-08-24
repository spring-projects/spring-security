/*
 * Copyright 2002-2019 the original author or authors.
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

import org.apache.http.HttpHeaders;
import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link LogoutConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 */
public class LogoutConfigurerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void configureWhenDefaultLogoutSuccessHandlerForHasNullLogoutHandlerThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(NullLogoutSuccessHandlerConfig.class).autowire())
				.withRootCauseInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void configureWhenDefaultLogoutSuccessHandlerForHasNullLogoutHandlerInLambdaThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(NullLogoutSuccessHandlerInLambdaConfig.class).autowire())
				.withRootCauseInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void configureWhenDefaultLogoutSuccessHandlerForHasNullMatcherThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(NullMatcherConfig.class).autowire())
				.withRootCauseInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void configureWhenDefaultLogoutSuccessHandlerForHasNullMatcherInLambdaThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(NullMatcherInLambdaConfig.class).autowire())
				.withRootCauseInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnLogoutFilter() {
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(LogoutFilter.class));
	}

	@Test
	public void logoutWhenInvokedTwiceThenUsesOriginalLogoutUrl() throws Exception {
		this.spring.register(DuplicateDoesNotOverrideConfig.class).autowire();
		MockHttpServletRequestBuilder logoutRequest = post("/custom/logout").with(csrf());
		// @formatter:off
		this.mvc.perform(logoutRequest)
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?logout"));
		// @formatter:on
	}

	// SEC-2311
	@Test
	public void logoutWhenGetRequestAndCsrfDisabledThenRedirectsToLogin() throws Exception {
		this.spring.register(CsrfDisabledConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(get("/logout"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?logout"));
		// @formatter:on
	}

	@Test
	public void logoutWhenPostRequestAndCsrfDisabledThenRedirectsToLogin() throws Exception {
		this.spring.register(CsrfDisabledConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(post("/logout"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?logout"));
		// @formatter:on
	}

	@Test
	public void logoutWhenPutRequestAndCsrfDisabledThenRedirectsToLogin() throws Exception {
		this.spring.register(CsrfDisabledConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(put("/logout"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?logout"));
		// @formatter:on
	}

	@Test
	public void logoutWhenDeleteRequestAndCsrfDisabledThenRedirectsToLogin() throws Exception {
		this.spring.register(CsrfDisabledConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(delete("/logout"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?logout"));
		// @formatter:on
	}

	@Test
	public void logoutWhenGetRequestAndCsrfDisabledAndCustomLogoutUrlThenRedirectsToLogin() throws Exception {
		this.spring.register(CsrfDisabledAndCustomLogoutConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(get("/custom/logout"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?logout"));
		// @formatter:on
	}

	@Test
	public void logoutWhenPostRequestAndCsrfDisabledAndCustomLogoutUrlThenRedirectsToLogin() throws Exception {
		this.spring.register(CsrfDisabledAndCustomLogoutConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(post("/custom/logout"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?logout"));
		// @formatter:on
	}

	@Test
	public void logoutWhenPutRequestAndCsrfDisabledAndCustomLogoutUrlThenRedirectsToLogin() throws Exception {
		this.spring.register(CsrfDisabledAndCustomLogoutConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(put("/custom/logout"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?logout"));
		// @formatter:on
	}

	@Test
	public void logoutWhenDeleteRequestAndCsrfDisabledAndCustomLogoutUrlThenRedirectsToLogin() throws Exception {
		this.spring.register(CsrfDisabledAndCustomLogoutConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(delete("/custom/logout"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?logout"));
		// @formatter:on
	}

	@Test
	public void logoutWhenCustomLogoutUrlInLambdaThenRedirectsToLogin() throws Exception {
		this.spring.register(CsrfDisabledAndCustomLogoutInLambdaConfig.class).autowire();
		// @formatter:off
		this.mvc.perform(get("/custom/logout"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?logout"));
		// @formatter:on
	}

	// SEC-3170
	@Test
	public void configureWhenLogoutHandlerNullThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(NullLogoutHandlerConfig.class).autowire())
				.withRootCauseInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void configureWhenLogoutHandlerNullInLambdaThenException() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.register(NullLogoutHandlerInLambdaConfig.class).autowire())
				.withRootCauseInstanceOf(IllegalArgumentException.class);
	}

	// SEC-3170
	@Test
	public void rememberMeWhenRememberMeServicesNotLogoutHandlerThenRedirectsToLogin() throws Exception {
		this.spring.register(RememberMeNoLogoutHandler.class).autowire();
		this.mvc.perform(post("/logout").with(csrf())).andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?logout"));
	}

	@Test
	public void logoutWhenAcceptTextHtmlThenRedirectsToLogin() throws Exception {
		this.spring.register(BasicSecurityConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder logoutRequest = post("/logout")
				.with(csrf())
				.with(user("user"))
				.header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE);
		this.mvc.perform(logoutRequest)
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?logout"));
		// @formatter:on
	}

	// gh-3282
	@Test
	public void logoutWhenAcceptApplicationJsonThenReturnsStatusNoContent() throws Exception {
		this.spring.register(BasicSecurityConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder request = post("/logout")
				.with(csrf())
				.with(user("user"))
				.header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
		// @formatter:on
		this.mvc.perform(request).andExpect(status().isNoContent());
	}

	// gh-4831
	@Test
	public void logoutWhenAcceptAllThenReturnsStatusNoContent() throws Exception {
		this.spring.register(BasicSecurityConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder logoutRequest = post("/logout")
				.with(csrf())
				.with(user("user"))
				.header(HttpHeaders.ACCEPT, MediaType.ALL_VALUE);
		// @formatter:on
		this.mvc.perform(logoutRequest).andExpect(status().isNoContent());
	}

	// gh-3902
	@Test
	public void logoutWhenAcceptFromChromeThenRedirectsToLogin() throws Exception {
		this.spring.register(BasicSecurityConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder request = post("/logout")
				.with(csrf())
				.with(user("user"))
				.header(HttpHeaders.ACCEPT, "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
		this.mvc.perform(request)
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?logout"));
		// @formatter:on
	}

	// gh-3997
	@Test
	public void logoutWhenXMLHttpRequestThenReturnsStatusNoContent() throws Exception {
		this.spring.register(BasicSecurityConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder request = post("/logout")
				.with(csrf())
				.with(user("user"))
				.header(HttpHeaders.ACCEPT, "text/html,application/json")
				.header("X-Requested-With", "XMLHttpRequest");
		// @formatter:on
		this.mvc.perform(request).andExpect(status().isNoContent());
	}

	@Test
	public void logoutWhenDisabledThenLogoutUrlNotFound() throws Exception {
		this.spring.register(LogoutDisabledConfig.class).autowire();
		this.mvc.perform(post("/logout").with(csrf())).andExpect(status().isNotFound());
	}

	@EnableWebSecurity
	static class NullLogoutSuccessHandlerConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.logout()
					.defaultLogoutSuccessHandlerFor(null, mock(RequestMatcher.class));
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class NullLogoutSuccessHandlerInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.logout((logout) ->
					logout.defaultLogoutSuccessHandlerFor(null, mock(RequestMatcher.class))
				);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class NullMatcherConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.logout()
					.defaultLogoutSuccessHandlerFor(mock(LogoutSuccessHandler.class), null);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class NullMatcherInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.logout((logout) ->
					logout.defaultLogoutSuccessHandlerFor(mock(LogoutSuccessHandler.class), null)
				);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class ObjectPostProcessorConfig extends WebSecurityConfigurerAdapter {

		static ObjectPostProcessor<Object> objectPostProcessor = spy(ReflectingObjectPostProcessor.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.logout();
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

	@EnableWebSecurity
	static class DuplicateDoesNotOverrideConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.logout()
					.logoutUrl("/custom/logout")
					.and()
				.logout();
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class CsrfDisabledConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf()
					.disable()
				.logout();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class CsrfDisabledAndCustomLogoutConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf()
					.disable()
				.logout()
					.logoutUrl("/custom/logout");
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class CsrfDisabledAndCustomLogoutInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.csrf()
					.disable()
				.logout((logout) -> logout.logoutUrl("/custom/logout"));
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class NullLogoutHandlerConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.logout()
					.addLogoutHandler(null);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class NullLogoutHandlerInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.logout((logout) -> logout.addLogoutHandler(null));
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class RememberMeNoLogoutHandler extends WebSecurityConfigurerAdapter {

		static RememberMeServices REMEMBER_ME = mock(RememberMeServices.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.rememberMe()
					.rememberMeServices(REMEMBER_ME);
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class BasicSecurityConfig extends WebSecurityConfigurerAdapter {

	}

	@EnableWebSecurity
	static class LogoutDisabledConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.logout()
					.disable();
			// @formatter:on
		}

	}

}
