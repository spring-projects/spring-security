/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.config.http;

import java.util.List;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Luke Taylor
 * @author Josh Cummings
 */
public class FormLoginConfigTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/FormLoginConfigTests";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void getProtectedPageWhenFormLoginConfiguredThenRedirectsToDefaultLoginPage() throws Exception {
		this.spring.configLocations(this.xml("WithAntRequestMatcher")).autowire();
		// @formatter:off
		this.mvc.perform(get("/"))
				.andExpect(redirectedUrl("http://localhost/login"));
		// @formatter:on
	}

	@Test
	public void authenticateWhenDefaultTargetUrlConfiguredThenRedirectsAccordingly() throws Exception {
		this.spring.configLocations(this.xml("WithDefaultTargetUrl")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.param("username", "user")
				.param("password", "password")
				.with(csrf());
		this.mvc.perform(loginRequest)
				.andExpect(redirectedUrl("/default"));
		// @formatter:on
	}

	@Test
	public void authenticateWhenConfiguredWithSpelThenRedirectsAccordingly() throws Exception {
		this.spring.configLocations(this.xml("UsingSpel")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.param("username", "user")
				.param("password", "password")
				.with(csrf());
		this.mvc.perform(loginRequest)
				.andExpect(redirectedUrl(WebConfigUtilsTests.URL + "/default"));
		MockHttpServletRequestBuilder invalidPassword = post("/login")
				.param("username", "user")
				.param("password", "wrong")
				.with(csrf());
		this.mvc.perform(invalidPassword)
				.andExpect(redirectedUrl(WebConfigUtilsTests.URL + "/failure"));
		this.mvc.perform(get("/"))
				.andExpect(redirectedUrl("http://localhost" + WebConfigUtilsTests.URL + "/login"));
		// @formatter:on
	}

	@Test
	public void autowireWhenLoginPageIsMisconfiguredThenDetects() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.configLocations(this.xml("NoLeadingSlashLoginPage")).autowire());
	}

	@Test
	public void autowireWhenDefaultTargetUrlIsMisconfiguredThenDetects() {
		assertThatExceptionOfType(BeanCreationException.class)
				.isThrownBy(() -> this.spring.configLocations(this.xml("NoLeadingSlashDefaultTargetUrl")).autowire());
	}

	@Test
	public void authenticateWhenCustomHandlerBeansConfiguredThenInvokesAccordingly() throws Exception {
		this.spring.configLocations(this.xml("WithSuccessAndFailureHandlers")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.param("username", "user")
				.param("password", "password")
				.with(csrf());
		this.mvc.perform(loginRequest)
				.andExpect(status().isIAmATeapot());
		MockHttpServletRequestBuilder invalidPassword = post("/login")
				.param("username", "user")
				.param("password", "wrong")
				.with(csrf());
		this.mvc.perform(invalidPassword)
				.andExpect(status().isIAmATeapot());
		// @formatter:on
	}

	@Test
	public void authenticateWhenCustomUsernameAndPasswordParametersThenSucceeds() throws Exception {
		this.spring.configLocations(this.xml("WithUsernameAndPasswordParameters")).autowire();
		this.mvc.perform(post("/login").param("xname", "user").param("xpass", "password").with(csrf()))
				.andExpect(redirectedUrl("/"));
	}

	/**
	 * SEC-2919 - DefaultLoginGeneratingFilter incorrectly used if login-url="/login"
	 */
	@Test
	public void autowireWhenCustomLoginPageIsSlashLoginThenNoDefaultLoginPageGeneratingFilterIsWired()
			throws Exception {
		this.spring.configLocations(this.xml("ForSec2919")).autowire();
		this.mvc.perform(get("/login")).andExpect(content().string("teapot"));
		assertThat(getFilter(this.spring.getContext(), DefaultLoginPageGeneratingFilter.class)).isNull();
	}

	@Test
	public void authenticateWhenCsrfIsEnabledThenRequiresToken() throws Exception {
		this.spring.configLocations(this.xml("WithCsrfEnabled")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.param("username", "user")
				.param("password", "password");
		this.mvc.perform(loginRequest)
				.andExpect(status().isForbidden());
		// @formatter:on
	}

	@Test
	public void authenticateWhenCsrfIsDisabledThenDoesNotRequireToken() throws Exception {
		this.spring.configLocations(this.xml("WithCsrfDisabled")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.param("username", "user")
				.param("password", "password");
		this.mvc.perform(loginRequest)
				.andExpect(status().isFound());
		// @formatter:on
	}

	/**
	 * SEC-3147: authentication-failure-url should be contained "error" parameter if
	 * login-page="/login"
	 */
	@Test
	public void authenticateWhenLoginPageIsSlashLoginAndAuthenticationFailsThenRedirectContainsErrorParameter()
			throws Exception {
		this.spring.configLocations(this.xml("ForSec3147")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.param("username", "user")
				.param("password", "wrong")
				.with(csrf());
		this.mvc.perform(loginRequest)
				.andExpect(redirectedUrl("/login?error"));
		// @formatter:on
	}

	private Filter getFilter(ApplicationContext context, Class<? extends Filter> filterClass) {
		FilterChainProxy filterChain = context.getBean(BeanIds.FILTER_CHAIN_PROXY, FilterChainProxy.class);
		List<Filter> filters = filterChain.getFilters("/any");
		for (Filter filter : filters) {
			if (filter.getClass() == filterClass) {
				return filter;
			}
		}
		return null;
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	@RestController
	public static class LoginController {

		@GetMapping("/login")
		public String ok() {
			return "teapot";
		}

	}

	public static class TeapotAuthenticationHandler
			implements AuthenticationSuccessHandler, AuthenticationFailureHandler {

		@Override
		public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
				AuthenticationException exception) {
			response.setStatus(HttpStatus.I_AM_A_TEAPOT.value());
		}

		@Override
		public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
				Authentication authentication) {
			response.setStatus(HttpStatus.I_AM_A_TEAPOT.value());
		}

	}

}
