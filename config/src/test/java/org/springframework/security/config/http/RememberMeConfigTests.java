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

import java.util.Collections;

import javax.servlet.http.Cookie;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.FatalBeanException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.parsing.BeanDefinitionParsingException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.TestDataSource;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Luke Taylor
 * @author Rob Winch
 * @author Oliver Becker
 */
public class RememberMeConfigTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/RememberMeConfigTests";

	@Autowired
	MockMvc mvc;

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Test
	public void requestWithRememberMeWhenUsingCustomTokenRepositoryThenAutomaticallyReauthenticates() throws Exception {
		this.spring.configLocations(this.xml("WithTokenRepository")).autowire();
		MvcResult result = this.rememberAuthentication("user", "password")
				.andExpect(cookie().secure(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, false))
				.andReturn();
		Cookie cookie = rememberMeCookie(result);
		this.mvc.perform(get("/authenticated").cookie(cookie)).andExpect(status().isOk());
		JdbcTemplate template = this.spring.getContext().getBean(JdbcTemplate.class);
		int count = template.queryForObject("select count(*) from persistent_logins", int.class);
		assertThat(count).isEqualTo(1);
	}

	@Test
	public void requestWithRememberMeWhenUsingCustomDataSourceThenAutomaticallyReauthenticates() throws Exception {
		this.spring.configLocations(this.xml("WithDataSource")).autowire();
		TestDataSource dataSource = this.spring.getContext().getBean(TestDataSource.class);
		JdbcTemplate template = new JdbcTemplate(dataSource);
		template.execute(JdbcTokenRepositoryImpl.CREATE_TABLE_SQL);
		MvcResult result = this.rememberAuthentication("user", "password")
				.andExpect(cookie().secure(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, false))
				.andReturn();
		Cookie cookie = rememberMeCookie(result);
		this.mvc.perform(get("/authenticated").cookie(cookie)).andExpect(status().isOk());
		int count = template.queryForObject("select count(*) from persistent_logins", int.class);
		assertThat(count).isEqualTo(1);
	}

	@Test
	public void requestWithRememberMeWhenUsingAuthenticationSuccessHandlerThenInvokesHandler() throws Exception {
		this.spring.configLocations(this.xml("WithAuthenticationSuccessHandler")).autowire();
		TestDataSource dataSource = this.spring.getContext().getBean(TestDataSource.class);
		JdbcTemplate template = new JdbcTemplate(dataSource);
		template.execute(JdbcTokenRepositoryImpl.CREATE_TABLE_SQL);
		MvcResult result = this.rememberAuthentication("user", "password")
				.andExpect(cookie().secure(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, false))
				.andReturn();
		Cookie cookie = rememberMeCookie(result);
		this.mvc.perform(get("/authenticated").cookie(cookie)).andExpect(redirectedUrl("/target"));
		int count = template.queryForObject("select count(*) from persistent_logins", int.class);
		assertThat(count).isEqualTo(1);
	}

	@Test
	public void requestWithRememberMeWhenUsingCustomRememberMeServicesThenAuthenticates() throws Exception {
		// SEC-1281 - using key with external services
		this.spring.configLocations(this.xml("WithServicesRef")).autowire();
		MvcResult result = this.rememberAuthentication("user", "password")
				.andExpect(cookie().secure(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, false))
				.andExpect(cookie().maxAge(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, 5000))
				.andReturn();
		Cookie cookie = rememberMeCookie(result);
		this.mvc.perform(get("/authenticated").cookie(cookie)).andExpect(status().isOk());
		// SEC-909
		this.mvc.perform(post("/logout").cookie(cookie).with(csrf()))
				.andExpect(cookie().maxAge(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, 0))
				.andReturn();
	}

	@Test
	public void logoutWhenUsingRememberMeDefaultsThenCookieIsCancelled() throws Exception {
		this.spring.configLocations(this.xml("DefaultConfig")).autowire();
		MvcResult result = this.rememberAuthentication("user", "password").andReturn();
		Cookie cookie = rememberMeCookie(result);
		this.mvc.perform(post("/logout").cookie(cookie).with(csrf()))
				.andExpect(cookie().maxAge(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, 0));
	}

	@Test
	public void requestWithRememberMeWhenTokenValidityIsConfiguredThenCookieReflectsCorrectExpiration()
			throws Exception {
		this.spring.configLocations(this.xml("TokenValidity")).autowire();
		MvcResult result = this.rememberAuthentication("user", "password")
				.andExpect(cookie().maxAge(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, 10000))
				.andReturn();
		Cookie cookie = rememberMeCookie(result);
		this.mvc.perform(get("/authenticated").cookie(cookie)).andExpect(status().isOk());
	}

	@Test
	public void requestWithRememberMeWhenTokenValidityIsNegativeThenCookieReflectsCorrectExpiration() throws Exception {
		this.spring.configLocations(this.xml("NegativeTokenValidity")).autowire();
		this.rememberAuthentication("user", "password")
				.andExpect(cookie().maxAge(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, -1));
	}

	@Test
	public void configureWhenUsingDataSourceAndANegativeTokenValidityThenThrowsWiringException() {
		assertThatExceptionOfType(FatalBeanException.class).isThrownBy(
				() -> this.spring.configLocations(this.xml("NegativeTokenValidityWithDataSource")).autowire());
	}

	@Test
	public void requestWithRememberMeWhenTokenValidityIsResolvedByPropertyPlaceholderThenCookieReflectsCorrectExpiration()
			throws Exception {
		this.spring.configLocations(this.xml("Sec2165")).autowire();
		this.rememberAuthentication("user", "password")
				.andExpect(cookie().maxAge(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, 30));
	}

	@Test
	public void requestWithRememberMeWhenUseSecureCookieIsTrueThenCookieIsSecure() throws Exception {
		this.spring.configLocations(this.xml("SecureCookie")).autowire();
		this.rememberAuthentication("user", "password")
				.andExpect(cookie().secure(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, true));
	}

	/**
	 * SEC-1827
	 */
	@Test
	public void requestWithRememberMeWhenUseSecureCookieIsFalseThenCookieIsNotSecure() throws Exception {
		this.spring.configLocations(this.xml("Sec1827")).autowire();
		this.rememberAuthentication("user", "password")
				.andExpect(cookie().secure(AbstractRememberMeServices.SPRING_SECURITY_REMEMBER_ME_COOKIE_KEY, false));
	}

	@Test
	public void configureWhenUsingPersistentTokenRepositoryAndANegativeTokenValidityThenThrowsWiringException() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class).isThrownBy(() -> this.spring
				.configLocations(this.xml("NegativeTokenValidityWithPersistentRepository")).autowire());
	}

	@Test
	public void requestWithRememberMeWhenUsingCustomUserDetailsServiceThenInvokesThisUserDetailsService()
			throws Exception {
		this.spring.configLocations(this.xml("WithUserDetailsService")).autowire();
		UserDetailsService userDetailsService = this.spring.getContext().getBean(UserDetailsService.class);
		given(userDetailsService.loadUserByUsername("user"))
				.willAnswer((invocation) -> new User("user", "{noop}password", Collections.emptyList()));
		MvcResult result = this.rememberAuthentication("user", "password").andReturn();
		Cookie cookie = rememberMeCookie(result);
		this.mvc.perform(get("/authenticated").cookie(cookie)).andExpect(status().isOk());
		verify(userDetailsService, atLeastOnce()).loadUserByUsername("user");
	}

	/**
	 * SEC-742
	 */
	@Test
	public void requestWithRememberMeWhenExcludingBasicAuthenticationFilterThenStillReauthenticates() throws Exception {
		this.spring.configLocations(this.xml("Sec742")).autowire();
		MvcResult result = this.mvc.perform(login("user", "password").param("remember-me", "true").with(csrf()))
				.andExpect(redirectedUrl("/messageList.html")).andReturn();
		Cookie cookie = rememberMeCookie(result);
		this.mvc.perform(get("/authenticated").cookie(cookie)).andExpect(status().isOk());
	}

	/**
	 * SEC-2119
	 */
	@Test
	public void requestWithRememberMeWhenUsingCustomRememberMeParameterThenReauthenticates() throws Exception {
		this.spring.configLocations(this.xml("WithRememberMeParameter")).autowire();
		MvcResult result = this.mvc
				.perform(login("user", "password").param("custom-remember-me-parameter", "true").with(csrf()))
				.andExpect(redirectedUrl("/")).andReturn();
		Cookie cookie = rememberMeCookie(result);
		this.mvc.perform(get("/authenticated").cookie(cookie)).andExpect(status().isOk());
	}

	@Test
	public void configureWhenUsingRememberMeParameterAndServicesRefThenThrowsWiringException() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class).isThrownBy(
				() -> this.spring.configLocations(this.xml("WithRememberMeParameterAndServicesRef")).autowire());
	}

	/**
	 * SEC-2826
	 */
	@Test
	public void authenticateWhenUsingCustomRememberMeCookieNameThenIssuesCookieWithThatName() throws Exception {
		this.spring.configLocations(this.xml("WithRememberMeCookie")).autowire();
		this.rememberAuthentication("user", "password").andExpect(cookie().exists("custom-remember-me-cookie"));
	}

	/**
	 * SEC-2826
	 */
	@Test
	public void configureWhenUsingRememberMeCookieAndServicesRefThenThrowsWiringException() {
		assertThatExceptionOfType(BeanDefinitionParsingException.class)
				.isThrownBy(
						() -> this.spring.configLocations(this.xml("WithRememberMeCookieAndServicesRef")).autowire())
				.withMessageContaining(
						"Configuration problem: services-ref can't be used in combination with attributes "
								+ "token-repository-ref,data-source-ref, user-service-ref, token-validity-seconds, "
								+ "use-secure-cookie, remember-me-parameter or remember-me-cookie");
	}

	private ResultActions rememberAuthentication(String username, String password) throws Exception {
		return this.mvc.perform(
				login(username, password).param(AbstractRememberMeServices.DEFAULT_PARAMETER, "true").with(csrf()))
				.andExpect(redirectedUrl("/"));
	}

	private static MockHttpServletRequestBuilder login(String username, String password) {
		return post("/login").param("username", username).param("password", password);
	}

	private static Cookie rememberMeCookie(MvcResult result) {
		return result.getResponse().getCookie("remember-me");
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	@RestController
	static class BasicController {

		@GetMapping("/authenticated")
		String ok() {
			return "ok";
		}

	}

}
