/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.config.annotation.web.configuration.ignore;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.stereotype.Controller;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * @author Manuel Jordan
 * @since 5.5
 */
public class AntPathRequestMatcherIgnoreConfigurationTests {

	private static final Log logger = LogFactory.getLog(AntPathRequestMatcherIgnoreConfigurationTests.class);

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mockMvc;

	/**
	 * This test is really only based about the {@code user} and his {@code password}
	 * verification, the roles are ignored, it could be valid or invalid. See
	 * {@link WebSecurityWithIgnoring#configure(AuthenticationManagerBuilder)
	 * configure(AuthenticationManagerBuilder)} for more details. For the rest of the
	 * tests based on the {@link WebSecurityWithIgnoring} class, the {@code user} and his
	 * {@code password} are ignored, therefore the tests are based on the roles to pass or
	 * fail.
	 * @throws Exception exception
	 */
	@Test
	public void webSecurityWithIgnoringAuthentication() throws Exception {
		logger.info("webSecurityWithIgnoringAuthentication [Test]");
		this.spring.register(WebSecurityWithIgnoring.class).autowire();

		AuthenticationManager authenticationManager = this.spring.getContext().getBean(AuthenticationManager.class);

		// @formatter:off
		logger.info(LogMessage.format("authenticationManager [CanonicalName]: %s%n",
				authenticationManager.getClass().getCanonicalName()));
		Authentication authentication = null;
		authentication =
				authenticationManager.authenticate(
						new UsernamePasswordAuthenticationToken(
								"user", "password", AuthorityUtils.createAuthorityList("ROLE_USER")));
		assertThat(authentication.isAuthenticated()).isTrue();

		authentication = null;
		authentication =
				authenticationManager.authenticate(
						new UsernamePasswordAuthenticationToken(
								"user", "password", AuthorityUtils.createAuthorityList("ROLE_NOT_DECLARED")));
		assertThat(authentication.isAuthenticated()).isTrue();

		authentication = null;
		authentication =
				authenticationManager.authenticate(
						new UsernamePasswordAuthenticationToken(
								"admin", "password", AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_ADMIN")));
		assertThat(authentication.isAuthenticated()).isTrue();

		try {
			authentication = null;
			authentication =
					authenticationManager.authenticate(
							new UsernamePasswordAuthenticationToken(
									"ghost", "password", AuthorityUtils.createAuthorityList("ROLE_GHOST")));
		}
		catch (BadCredentialsException ex) {
			assertThat(ex.getMessage()).isEqualTo("Bad credentials");
			assertThat(authentication).isNull();
		}

		try {
			authentication = null;
			authentication =
					authenticationManager.authenticate(
							new UsernamePasswordAuthenticationToken(
									"oversight", "password", AuthorityUtils.createAuthorityList("ROLE_OVERSIGHT")));
		}
		catch (BadCredentialsException ex) {
			assertThat(ex.getMessage()).isEqualTo("Bad credentials");
			assertThat(authentication).isNull();
		}

		try {
			authentication = null;
			authentication =
					authenticationManager.authenticate(
							new UsernamePasswordAuthenticationToken(
									"other", "password", AuthorityUtils.createAuthorityList("ROLE_OTHER")));
		}
		catch (BadCredentialsException ex) {
			assertThat(ex.getMessage()).isEqualTo("Bad credentials");
			assertThat(authentication).isNull();
		}
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithIgnoringForSomething() throws Exception {
		logger.info("webSecurityWithIgnoringForSomething [Test]");
		this.spring.register(WebSecurityWithIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("something/something"))
					.andExpect(forwardedUrl("something/something"))
					.andReturn();

		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("something/something"))
					.andExpect(forwardedUrl("something/something"))
					.andReturn();

		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithIgnoringForHome() throws Exception {
		logger.info("webSecurityWithIgnoringForHome [Test]");
		this.spring.register(WebSecurityWithIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/home")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("home/home"))
					.andExpect(forwardedUrl("home/home"))
					.andReturn();

		this.mockMvc.perform(
					get("/home")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("home/home"))
					.andExpect(forwardedUrl("home/home"))
					.andReturn();

		this.mockMvc.perform(
					get("/home")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("home/home"))
					.andExpect(forwardedUrl("home/home"))
					.andReturn();

		this.mockMvc.perform(
					get("/home")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("home/home"))
					.andExpect(forwardedUrl("home/home"))
					.andReturn();

		this.mockMvc.perform(
					get("/home")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("home/home"))
					.andExpect(forwardedUrl("home/home"))
					.andReturn();

		this.mockMvc.perform(
					get("/home")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("home/home"))
					.andExpect(forwardedUrl("home/home"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithIgnoringForSearch() throws Exception {
		logger.info("webSecurityWithIgnoringForSearch [Test]");
		this.spring.register(WebSecurityWithIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/search/alpha")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("search/search"))
					.andExpect(forwardedUrl("search/search"))
					.andReturn();

		this.mockMvc.perform(
					get("/search/alpha")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/search/alpha")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("search/search"))
					.andExpect(forwardedUrl("search/search"))
					.andReturn();

		this.mockMvc.perform(
					get("/search/alpha")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/search/alpha")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("search/search"))
					.andExpect(forwardedUrl("search/search"))
					.andReturn();

		this.mockMvc.perform(
					get("/search/alpha")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/search/beta")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("search/search"))
					.andExpect(forwardedUrl("search/search"))
					.andReturn();

		this.mockMvc.perform(
					get("/search/beta")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/search/beta")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("search/search"))
					.andExpect(forwardedUrl("search/search"))
					.andReturn();

		this.mockMvc.perform(
					get("/search/beta")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/search/beta")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("search/search"))
					.andExpect(forwardedUrl("search/search"))
					.andReturn();

		this.mockMvc.perform(
					get("/search/beta")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithIgnoringForNotification() throws Exception {
		logger.info("webSecurityWithIgnoringForNotification [Test]");
		this.spring.register(WebSecurityWithIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithIgnoringForReport() throws Exception {
		logger.info("webSecurityWithIgnoringForReport [Test]");
		this.spring.register(WebSecurityWithIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithIgnoringForContact() throws Exception {
		logger.info("webSecurityWithIgnoringForContact [Test]");
		this.spring.register(WebSecurityWithIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("contact/contact"))
					.andExpect(forwardedUrl("contact/contact"))
					.andReturn();

		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("contact/contact"))
					.andExpect(forwardedUrl("contact/contact"))
					.andReturn();

		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("contact/contact"))
					.andExpect(forwardedUrl("contact/contact"))
					.andReturn();

		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("contact/contact"))
					.andExpect(forwardedUrl("contact/contact"))
					.andReturn();

		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("contact/contact"))
					.andExpect(forwardedUrl("contact/contact"))
					.andReturn();

		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("contact/contact"))
					.andExpect(forwardedUrl("contact/contact"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithIgnoringForAbout() throws Exception {
		logger.info("webSecurityWithIgnoringForAbout [Test]");
		this.spring.register(WebSecurityWithIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("about/about"))
					.andExpect(forwardedUrl("about/about"))
					.andReturn();

		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("about/about"))
					.andExpect(forwardedUrl("about/about"))
					.andReturn();

		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("about/about"))
					.andExpect(forwardedUrl("about/about"))
					.andReturn();

		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("about/about"))
					.andExpect(forwardedUrl("about/about"))
					.andReturn();

		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("about/about"))
					.andExpect(forwardedUrl("about/about"))
					.andReturn();

		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("about/about"))
					.andExpect(forwardedUrl("about/about"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithIgnoringForBlog() throws Exception {
		logger.info("webSecurityWithIgnoringForBlog [Test]");
		this.spring.register(WebSecurityWithIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();

		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();

		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();

		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();

		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();

		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithIgnoringForOther() throws Exception {
		logger.info("webSecurityWithIgnoringForOther [Test]");
		this.spring.register(WebSecurityWithIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("other/other"))
					.andExpect(forwardedUrl("other/other"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithIgnoringForDelete() throws Exception {
		logger.info("webSecurityWithIgnoringForDelete [Test]");
		this.spring.register(WebSecurityWithIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("delete/delete"))
					.andExpect(forwardedUrl("delete/delete"))
					.andReturn();

		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("remove/remove"))
					.andExpect(forwardedUrl("remove/remove"))
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithIgnoringForPost() throws Exception {
		logger.info("webSecurityWithIgnoringForPost [Test]");
		this.spring.register(WebSecurityWithIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("post/post"))
					.andExpect(forwardedUrl("post/post"))
					.andReturn();

		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("save/save"))
					.andExpect(forwardedUrl("save/save"))
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithIgnoringForPut() throws Exception {
		logger.info("webSecurityWithIgnoringForPut [Test]");
		this.spring.register(WebSecurityWithIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("put/put"))
					.andExpect(forwardedUrl("put/put"))
					.andReturn();

		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("update/update"))
					.andExpect(forwardedUrl("update/update"))
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithIgnoringForPatch() throws Exception {
		logger.info("webSecurityWithIgnoringForPatch [Test]");
		this.spring.register(WebSecurityWithIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("patch/patch"))
					.andExpect(forwardedUrl("patch/patch"))
					.andReturn();

		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("patch/patch"))
					.andExpect(forwardedUrl("patch/patch"))
					.andReturn();

		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("patch/patch"))
					.andExpect(forwardedUrl("patch/patch"))
					.andReturn();

		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("patch/patch"))
					.andExpect(forwardedUrl("patch/patch"))
					.andReturn();

		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("patch/patch"))
					.andExpect(forwardedUrl("patch/patch"))
					.andReturn();

		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("patch/patch"))
					.andExpect(forwardedUrl("patch/patch"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * This test is really only based about the {@code user} and his {@code password}
	 * verification, the roles are ignored, it could be valid or invalid. See
	 * {@link WebSecurityWithoutIgnoring#configure(AuthenticationManagerBuilder)
	 * configure(AuthenticationManagerBuilder)} for more details. For the rest of the
	 * tests based on the {@link WebSecurityWithoutIgnoring} class, the {@code user} and
	 * his {@code password} are ignored, therefore the test is based on the roles to pass
	 * or fail.
	 * @throws Exception exception
	 */
	@Test
	public void webSecurityWithoutIgnoringAuthentication() throws Exception {
		logger.info("webSecurityWithoutIgnoringAuthentication [Test]");
		this.spring.register(WebSecurityWithoutIgnoring.class).autowire();

		AuthenticationManager authenticationManager = this.spring.getContext().getBean(AuthenticationManager.class);

		// @formatter:off
		logger.info(LogMessage.format("authenticationManager [CanonicalName]: %s%n",
				authenticationManager.getClass().getCanonicalName()));
		Authentication authentication = null;
		authentication =
				authenticationManager.authenticate(
						new UsernamePasswordAuthenticationToken(
								"user", "password", AuthorityUtils.createAuthorityList("ROLE_USER")));
		assertThat(authentication.isAuthenticated()).isTrue();

		authentication = null;
		authentication =
				authenticationManager.authenticate(
						new UsernamePasswordAuthenticationToken(
								"user", "password", AuthorityUtils.createAuthorityList("ROLE_NOT_DECLARED")));
		assertThat(authentication.isAuthenticated()).isTrue();

		authentication = null;
		authentication =
				authenticationManager.authenticate(
						new UsernamePasswordAuthenticationToken(
								"admin", "password", AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_ADMIN")));
		assertThat(authentication.isAuthenticated()).isTrue();

		try {
			authentication = null;
			authentication =
					authenticationManager.authenticate(
							new UsernamePasswordAuthenticationToken(
									"ghost", "password", AuthorityUtils.createAuthorityList("ROLE_GHOST")));
		}
		catch (BadCredentialsException ex) {
			assertThat(ex.getMessage()).isEqualTo("Bad credentials");
			assertThat(authentication).isNull();
		}

		try {
			authentication = null;
			authentication =
					authenticationManager.authenticate(
							new UsernamePasswordAuthenticationToken(
									"oversight", "password", AuthorityUtils.createAuthorityList("ROLE_OVERSIGHT")));
		}
		catch (BadCredentialsException ex) {
			assertThat(ex.getMessage()).isEqualTo("Bad credentials");
			assertThat(authentication).isNull();
		}

		try {
			authentication = null;
			authentication =
					authenticationManager.authenticate(
							new UsernamePasswordAuthenticationToken(
									"other", "password", AuthorityUtils.createAuthorityList("ROLE_OTHER")));
		}
		catch (BadCredentialsException ex) {
			assertThat(ex.getMessage()).isEqualTo("Bad credentials");
			assertThat(authentication).isNull();
		}
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithoutIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithoutIgnoringForSomething() throws Exception {
		logger.info("webSecurityWithoutIgnoringForSomething [Test]");
		this.spring.register(WebSecurityWithoutIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("something/something"))
					.andExpect(forwardedUrl("something/something"))
					.andReturn();

		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("something/something"))
					.andExpect(forwardedUrl("something/something"))
					.andReturn();

		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithoutIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithoutIgnoringForHome() throws Exception {
		logger.info("webSecurityWithoutIgnoringForHome [Test]");
		this.spring.register(WebSecurityWithoutIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
				get("/home")
				.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("home/home"))
				.andExpect(forwardedUrl("home/home"))
				.andReturn();

		this.mockMvc.perform(
				get("/home")
				.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("home/home"))
				.andExpect(forwardedUrl("home/home"))
				.andReturn();

		this.mockMvc.perform(
				get("/home")
				.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("home/home"))
				.andExpect(forwardedUrl("home/home"))
				.andReturn();

		this.mockMvc.perform(
				get("/home")
				.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("home/home"))
				.andExpect(forwardedUrl("home/home"))
				.andReturn();

		this.mockMvc.perform(
				get("/home")
				.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("home/home"))
				.andExpect(forwardedUrl("home/home"))
				.andReturn();

		this.mockMvc.perform(
				get("/home")
				.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("home/home"))
				.andExpect(forwardedUrl("home/home"))
				.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithoutIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithoutIgnoringForSearch() throws Exception {
		logger.info("webSecurityWithoutIgnoringForSearch [Test]");
		this.spring.register(WebSecurityWithoutIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
				get("/search/alpha")
				.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();

		this.mockMvc.perform(
				get("/search/alpha")
				.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
				.andDo(print())
				.andExpect(status().isForbidden())
				.andReturn();

		this.mockMvc.perform(
				get("/search/alpha")
				.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();

		this.mockMvc.perform(
				get("/search/alpha")
				.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
				.andDo(print())
				.andExpect(status().isForbidden())
				.andReturn();

		this.mockMvc.perform(
				get("/search/alpha")
				.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();

		this.mockMvc.perform(
				get("/search/alpha")
				.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
				.andDo(print())
				.andExpect(status().isForbidden())
				.andReturn();

		this.mockMvc.perform(
				get("/search/beta")
				.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();

		this.mockMvc.perform(
				get("/search/beta")
				.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
				.andDo(print())
				.andExpect(status().isForbidden())
				.andReturn();

		this.mockMvc.perform(
				get("/search/beta")
				.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();

		this.mockMvc.perform(
				get("/search/beta")
				.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
				.andDo(print())
				.andExpect(status().isForbidden())
				.andReturn();

		this.mockMvc.perform(
				get("/search/beta")
				.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();

		this.mockMvc.perform(
				get("/search/beta")
				.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
				.andDo(print())
				.andExpect(status().isForbidden())
				.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithoutIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithoutIgnoringForNotification() throws Exception {
		logger.info("webSecurityWithoutIgnoringForNotification [Test]");
		this.spring.register(WebSecurityWithoutIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithoutIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithoutIgnoringForReport() throws Exception {
		logger.info("webSecurityWithoutIgnoringForReport [Test]");
		this.spring.register(WebSecurityWithoutIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithoutIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithoutIgnoringForContact() throws Exception {
		logger.info("webSecurityWithoutIgnoringForContact [Test]");
		this.spring.register(WebSecurityWithoutIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("contact/contact"))
					.andExpect(forwardedUrl("contact/contact"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithoutIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithoutIgnoringForAbout() throws Exception {
		logger.info("webSecurityWithoutIgnoringForAbout [Test]");
		this.spring.register(WebSecurityWithoutIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("about/about"))
					.andExpect(forwardedUrl("about/about"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithoutIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithoutIgnoringForBlog() throws Exception {
		logger.info("webSecurityWithoutIgnoringForBlog [Test]");
		this.spring.register(WebSecurityWithoutIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();

		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();

		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();

		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();

		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();

		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithoutIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithoutIgnoringForOther() throws Exception {
		logger.info("webSecurityWithoutIgnoringForOther [Test]");
		this.spring.register(WebSecurityWithoutIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("other/other"))
					.andExpect(forwardedUrl("other/other"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithoutIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithoutIgnoringForDelete() throws Exception {
		logger.info("webSecurityWithoutIgnoringForDelete [Test]");
		this.spring.register(WebSecurityWithoutIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("delete/delete"))
					.andExpect(forwardedUrl("delete/delete"))
					.andReturn();

		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("remove/remove"))
					.andExpect(forwardedUrl("remove/remove"))
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithoutIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithoutIgnoringForPost() throws Exception {
		logger.info("webSecurityWithoutIgnoringForPost [Test]");
		this.spring.register(WebSecurityWithoutIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("post/post"))
					.andExpect(forwardedUrl("post/post"))
					.andReturn();

		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("save/save"))
					.andExpect(forwardedUrl("save/save"))
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithoutIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithoutIgnoringForPut() throws Exception {
		logger.info("webSecurityWithoutIgnoringForPut [Test]");
		this.spring.register(WebSecurityWithoutIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("put/put"))
					.andExpect(forwardedUrl("put/put"))
					.andReturn();

		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("update/update"))
					.andExpect(forwardedUrl("update/update"))
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithoutIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithoutIgnoringForPatch() throws Exception {
		logger.info("webSecurityWithoutIgnoringForPatch [Test]");
		this.spring.register(WebSecurityWithoutIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isForbidden())
					.andReturn();

		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("patch/patch"))
					.andExpect(forwardedUrl("patch/patch"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * This test is really only based about the {@code user} and his {@code password}
	 * verification, the roles are ignored, it could be valid or invalid. See
	 * {@link WebSecurityWithGlobalIgnoring#configure(AuthenticationManagerBuilder)
	 * configure(AuthenticationManagerBuilder)} for more details. For the rest of the
	 * tests based on the {@link WebSecurityWithGlobalIgnoring} class, the {@code user}
	 * and his {@code password} are ignored, therefore the test is based on the roles to
	 * pass or fail.
	 * @throws Exception exception
	 */
	@Test
	public void webSecurityWithGlobalIgnoringAuthentication() throws Exception {
		logger.info("webSecurityWithGlobalIgnoringAuthentication [Test]");
		this.spring.register(WebSecurityWithGlobalIgnoring.class).autowire();

		AuthenticationManager authenticationManager = this.spring.getContext().getBean(AuthenticationManager.class);

		// @formatter:off
		logger.info(LogMessage.format("authenticationManager [CanonicalName]: %s%n",
				authenticationManager.getClass().getCanonicalName()));
		Authentication authentication = null;
		authentication =
				authenticationManager.authenticate(
						new UsernamePasswordAuthenticationToken(
								"user", "password", AuthorityUtils.createAuthorityList("ROLE_USER")));
		assertThat(authentication.isAuthenticated()).isTrue();

		authentication = null;
		authentication =
				authenticationManager.authenticate(
						new UsernamePasswordAuthenticationToken(
								"user", "password", AuthorityUtils.createAuthorityList("ROLE_NOT_DECLARED")));
		assertThat(authentication.isAuthenticated()).isTrue();

		authentication = null;
		authentication =
				authenticationManager.authenticate(
						new UsernamePasswordAuthenticationToken(
								"admin", "password", AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_ADMIN")));
		assertThat(authentication.isAuthenticated()).isTrue();

		try {
			authentication = null;
			authentication =
					authenticationManager.authenticate(
							new UsernamePasswordAuthenticationToken(
									"ghost", "password", AuthorityUtils.createAuthorityList("ROLE_GHOST")));
		}
		catch (BadCredentialsException ex) {
			assertThat(ex.getMessage()).isEqualTo("Bad credentials");
			assertThat(authentication).isNull();
		}

		try {
			authentication = null;
			authentication =
					authenticationManager.authenticate(
							new UsernamePasswordAuthenticationToken(
									"oversight", "password", AuthorityUtils.createAuthorityList("ROLE_OVERSIGHT")));
		}
		catch (BadCredentialsException ex) {
			assertThat(ex.getMessage()).isEqualTo("Bad credentials");
			assertThat(authentication).isNull();
		}

		try {
			authentication = null;
			authentication =
					authenticationManager.authenticate(
							new UsernamePasswordAuthenticationToken(
									"other", "password", AuthorityUtils.createAuthorityList("ROLE_OTHER")));
		}
		catch (BadCredentialsException ex) {
			assertThat(ex.getMessage()).isEqualTo("Bad credentials");
			assertThat(authentication).isNull();
		}
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithGlobalIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithGlobalIgnoringForSomething() throws Exception {
		logger.info("webSecurityWithGlobalIgnoringForSomething [Test]");
		this.spring.register(WebSecurityWithGlobalIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("something/something"))
					.andExpect(forwardedUrl("something/something"))
					.andReturn();

		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("something/something"))
					.andExpect(forwardedUrl("something/something"))
					.andReturn();

		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("something/something"))
					.andExpect(forwardedUrl("something/something"))
					.andReturn();

		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("something/something"))
					.andExpect(forwardedUrl("something/something"))
					.andReturn();

		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("something/something"))
					.andExpect(forwardedUrl("something/something"))
					.andReturn();

		this.mockMvc.perform(
					get("/something")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("something/something"))
					.andExpect(forwardedUrl("something/something"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithGlobalIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithGlobalIgnoringForHome() throws Exception {
		logger.info("webSecurityWithGlobalIgnoringForHome [Test]");
		this.spring.register(WebSecurityWithGlobalIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
				get("/home")
				.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("home/home"))
				.andExpect(forwardedUrl("home/home"))
				.andReturn();

		this.mockMvc.perform(
				get("/home")
				.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("home/home"))
				.andExpect(forwardedUrl("home/home"))
				.andReturn();

		this.mockMvc.perform(
				get("/home")
				.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("home/home"))
				.andExpect(forwardedUrl("home/home"))
				.andReturn();

		this.mockMvc.perform(
				get("/home")
				.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("home/home"))
				.andExpect(forwardedUrl("home/home"))
				.andReturn();

		this.mockMvc.perform(
				get("/home")
				.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("home/home"))
				.andExpect(forwardedUrl("home/home"))
				.andReturn();

		this.mockMvc.perform(
				get("/home")
				.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("home/home"))
				.andExpect(forwardedUrl("home/home"))
				.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithGlobalIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithGlobalIgnoringForSearch() throws Exception {
		logger.info("webSecurityWithGlobalIgnoringForSearch [Test]");
		this.spring.register(WebSecurityWithGlobalIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
				get("/search/alpha")
				.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();

		this.mockMvc.perform(
				get("/search/alpha")
				.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();

		this.mockMvc.perform(
				get("/search/alpha")
				.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();

		this.mockMvc.perform(
				get("/search/alpha")
				.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();

		this.mockMvc.perform(
				get("/search/alpha")
				.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();

		this.mockMvc.perform(
				get("/search/alpha")
				.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();

		this.mockMvc.perform(
				get("/search/beta")
				.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();

		this.mockMvc.perform(
				get("/search/beta")
				.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();

		this.mockMvc.perform(
				get("/search/beta")
				.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();

		this.mockMvc.perform(
				get("/search/beta")
				.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();

		this.mockMvc.perform(
				get("/search/beta")
				.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();

		this.mockMvc.perform(
				get("/search/beta")
				.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
				.andDo(print())
				.andExpect(status().isOk())
				.andExpect(view().name("search/search"))
				.andExpect(forwardedUrl("search/search"))
				.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithGlobalIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithGlobalIgnoringForNotification() throws Exception {
		logger.info("webSecurityWithGlobalIgnoringForNotification [Test]");
		this.spring.register(WebSecurityWithGlobalIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/alpha")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();

		this.mockMvc.perform(
					get("/notification/beta")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("notification/notification"))
					.andExpect(forwardedUrl("notification/notification"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithGlobalIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithGlobalIgnoringForReport() throws Exception {
		logger.info("webSecurityWithGlobalIgnoringForReport [Test]");
		this.spring.register(WebSecurityWithGlobalIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/alpha")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();

		this.mockMvc.perform(
					get("/report/beta")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("report/report"))
					.andExpect(forwardedUrl("report/report"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithGlobalIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithGlobalIgnoringForContact() throws Exception {
		logger.info("webSecurityWithGlobalIgnoringForContact [Test]");
		this.spring.register(WebSecurityWithGlobalIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("contact/contact"))
					.andExpect(forwardedUrl("contact/contact"))
					.andReturn();

		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("contact/contact"))
					.andExpect(forwardedUrl("contact/contact"))
					.andReturn();

		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("contact/contact"))
					.andExpect(forwardedUrl("contact/contact"))
					.andReturn();

		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("contact/contact"))
					.andExpect(forwardedUrl("contact/contact"))
					.andReturn();

		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("contact/contact"))
					.andExpect(forwardedUrl("contact/contact"))
					.andReturn();

		this.mockMvc.perform(
					get("/contact")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("contact/contact"))
					.andExpect(forwardedUrl("contact/contact"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithGlobalIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithGlobalIgnoringForAbout() throws Exception {
		logger.info("webSecurityWithGlobalIgnoringForAbout [Test]");
		this.spring.register(WebSecurityWithGlobalIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("about/about"))
					.andExpect(forwardedUrl("about/about"))
					.andReturn();

		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("about/about"))
					.andExpect(forwardedUrl("about/about"))
					.andReturn();

		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("about/about"))
					.andExpect(forwardedUrl("about/about"))
					.andReturn();

		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("about/about"))
					.andExpect(forwardedUrl("about/about"))
					.andReturn();

		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("about/about"))
					.andExpect(forwardedUrl("about/about"))
					.andReturn();

		this.mockMvc.perform(
					get("/about")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("about/about"))
					.andExpect(forwardedUrl("about/about"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithGlobalIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithGlobalIgnoringForBlog() throws Exception {
		logger.info("webSecurityWithGlobalIgnoringForBlog [Test]");
		this.spring.register(WebSecurityWithGlobalIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();

		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();

		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();

		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();

		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();

		this.mockMvc.perform(
					get("/blog")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("blog/blog"))
					.andExpect(forwardedUrl("blog/blog"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithGlobalIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithGlobalIgnoringForOther() throws Exception {
		logger.info("webSecurityWithGlobalIgnoringForOther [Test]");
		this.spring.register(WebSecurityWithGlobalIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("other/other"))
					.andExpect(forwardedUrl("other/other"))
					.andReturn();

		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("other/other"))
					.andExpect(forwardedUrl("other/other"))
					.andReturn();

		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("other/other"))
					.andExpect(forwardedUrl("other/other"))
					.andReturn();

		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("other/other"))
					.andExpect(forwardedUrl("other/other"))
					.andReturn();

		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("other/other"))
					.andExpect(forwardedUrl("other/other"))
					.andReturn();

		this.mockMvc.perform(
					get("/other")
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("other/other"))
					.andExpect(forwardedUrl("other/other"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithGlobalIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithGlobalIgnoringForDelete() throws Exception {
		logger.info("webSecurityWithGlobalIgnoringForDelete [Test]");
		this.spring.register(WebSecurityWithGlobalIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("delete/delete"))
					.andExpect(forwardedUrl("delete/delete"))
					.andReturn();

		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("delete/delete"))
					.andExpect(forwardedUrl("delete/delete"))
					.andReturn();

		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("delete/delete"))
					.andExpect(forwardedUrl("delete/delete"))
					.andReturn();

		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("delete/delete"))
					.andExpect(forwardedUrl("delete/delete"))
					.andReturn();

		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("delete/delete"))
					.andExpect(forwardedUrl("delete/delete"))
					.andReturn();

		this.mockMvc.perform(
					delete("/delete/{id}", "5")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("delete/delete"))
					.andExpect(forwardedUrl("delete/delete"))
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("remove/remove"))
					.andExpect(forwardedUrl("remove/remove"))
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("remove/remove"))
					.andExpect(forwardedUrl("remove/remove"))
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("remove/remove"))
					.andExpect(forwardedUrl("remove/remove"))
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("remove/remove"))
					.andExpect(forwardedUrl("remove/remove"))
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("remove/remove"))
					.andExpect(forwardedUrl("remove/remove"))
					.andReturn();

		this.mockMvc.perform(
					delete("/remove/{id}", "7")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("remove/remove"))
					.andExpect(forwardedUrl("remove/remove"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithGlobalIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithGlobalIgnoringForPost() throws Exception {
		logger.info("webSecurityWithGlobalIgnoringForPost [Test]");
		this.spring.register(WebSecurityWithGlobalIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("post/post"))
					.andExpect(forwardedUrl("post/post"))
					.andReturn();

		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("post/post"))
					.andExpect(forwardedUrl("post/post"))
					.andReturn();

		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("post/post"))
					.andExpect(forwardedUrl("post/post"))
					.andReturn();

		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("post/post"))
					.andExpect(forwardedUrl("post/post"))
					.andReturn();

		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("post/post"))
					.andExpect(forwardedUrl("post/post"))
					.andReturn();

		this.mockMvc.perform(
					post("/post")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("post/post"))
					.andExpect(forwardedUrl("post/post"))
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("save/save"))
					.andExpect(forwardedUrl("save/save"))
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("save/save"))
					.andExpect(forwardedUrl("save/save"))
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("save/save"))
					.andExpect(forwardedUrl("save/save"))
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("save/save"))
					.andExpect(forwardedUrl("save/save"))
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("save/save"))
					.andExpect(forwardedUrl("save/save"))
					.andReturn();

		this.mockMvc.perform(
					post("/save")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("save/save"))
					.andExpect(forwardedUrl("save/save"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithGlobalIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithGlobalIgnoringForPut() throws Exception {
		logger.info("webSecurityWithGlobalIgnoringForPut [Test]");
		this.spring.register(WebSecurityWithGlobalIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("put/put"))
					.andExpect(forwardedUrl("put/put"))
					.andReturn();

		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("put/put"))
					.andExpect(forwardedUrl("put/put"))
					.andReturn();

		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("put/put"))
					.andExpect(forwardedUrl("put/put"))
					.andReturn();

		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("put/put"))
					.andExpect(forwardedUrl("put/put"))
					.andReturn();

		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("put/put"))
					.andExpect(forwardedUrl("put/put"))
					.andReturn();

		this.mockMvc.perform(
					put("/put")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("put/put"))
					.andExpect(forwardedUrl("put/put"))
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("update/update"))
					.andExpect(forwardedUrl("update/update"))
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("update/update"))
					.andExpect(forwardedUrl("update/update"))
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("update/update"))
					.andExpect(forwardedUrl("update/update"))
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("update/update"))
					.andExpect(forwardedUrl("update/update"))
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("update/update"))
					.andExpect(forwardedUrl("update/update"))
					.andReturn();

		this.mockMvc.perform(
					put("/update")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("update/update"))
					.andExpect(forwardedUrl("update/update"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @throws Exception exception
	 * @see #webSecurityWithGlobalIgnoringAuthentication()
	 */
	@Test
	public void webSecurityWithGlobalIgnoringForPatch() throws Exception {
		logger.info("webSecurityWithGlobalIgnoringForPatch [Test]");
		this.spring.register(WebSecurityWithGlobalIgnoring.class).autowire();

		// @formatter:off
		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("patch/patch"))
					.andExpect(forwardedUrl("patch/patch"))
					.andReturn();

		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_NOT_DECLARED"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("patch/patch"))
					.andExpect(forwardedUrl("patch/patch"))
					.andReturn();

		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("admin", "password", "ROLE_USER", "ROLE_ADMIN"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("patch/patch"))
					.andExpect(forwardedUrl("patch/patch"))
					.andReturn();

		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("ghost", "password", "ROLE_GHOST"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("patch/patch"))
					.andExpect(forwardedUrl("patch/patch"))
					.andReturn();

		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("oversight", "password", "ROLE_OVERSIGHT"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("patch/patch"))
					.andExpect(forwardedUrl("patch/patch"))
					.andReturn();

		this.mockMvc.perform(
					patch("/patch/{id}", "7")
					.param("field1", "doesnotmatter")
					.param("field2", "doesnotmatter")
					.with(csrf())
					.with(authentication(new TestingAuthenticationToken("other", "password", "ROLE_OTHER"))))
					.andDo(print())
					.andExpect(status().isOk())
					.andExpect(view().name("patch/patch"))
					.andExpect(forwardedUrl("patch/patch"))
					.andReturn();
		// @formatter:on
	}

	/**
	 * @author Manuel Jordan
	 * @since 5.5
	 */
	@EnableWebMvc
	@EnableWebSecurity
	static class WebSecurityWithIgnoring extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication().withUser(PasswordEncodedUser.user()).withUser(PasswordEncodedUser.admin());
		}

		/**
		 * {@code antMatchers("/**").hasRole("OTHER")} really should be
		 * {@code antMatchers("/**").authenticated()}, but to test that really {@code /**}
		 * is being applied then {@code hasRole("OTHER")} is used.
		 *
		 * <p>
		 * DELETE, POST, PUT work with csrf, thus is mandatory use it or it can be
		 * ignored/avoid with {@code csrf().disable()}, otherwise those HTTP methods
		 * always fail with 403. Because is critical use csrf in production, the test
		 * methods for those HTTP methods use {@code .with(csrf())}
		 */
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http.authorizeRequests()
					.antMatchers("/something").hasRole("USER")
					.antMatchers("/home").authenticated()
					.antMatchers(HttpMethod.GET, "/search/alpha", "/search/beta").hasAnyRole("USER", "ADMIN", "OVERSIGHT")
					.antMatchers(HttpMethod.GET, "/notification/**", "/report/**").authenticated()
					.antMatchers(HttpMethod.POST).hasRole("ADMIN")//this approach only exists for 'antMatchers'
					.antMatchers(HttpMethod.PUT).hasRole("ADMIN")//this approach only exists for 'antMatchers'
					.antMatchers(HttpMethod.DELETE).hasRole("ADMIN")//this approach only exists for 'antMatchers'
					.antMatchers("/blog").permitAll()
					.antMatchers("/**").hasRole("OTHER")//should be 'authenticated()', but is used to be only applied to '/other'
					.and()
				.formLogin();
			// @formatter:on
		}

		/**
		 * For the {@code PATCH} http method is not mandatory use in its test
		 * {@code .with(csrf())}, it because is already ignored.
		 */
		@Override
		public void configure(WebSecurity web) throws Exception {
			// @formatter:off
			web.ignoring().antMatchers("/css/**", "/js/**")
						.antMatchers(HttpMethod.GET, "/about", "/contact")
						.antMatchers(HttpMethod.PATCH); // this approach only exists for 'antMatchers'
			// @formatter:on
		}

		@Bean
		@Override
		public AuthenticationManager authenticationManagerBean() throws Exception {
			return super.authenticationManagerBean();
		}

		@Controller
		static class WebUniverseController {

			@GetMapping(path = "/home")
			String home(Model model) {
				return "home/home";
			}

			@GetMapping(path = "/something")
			String something(Model model) {
				return "something/something";
			}

			@GetMapping(path = "/blog")
			String blog(Model model) {
				return "blog/blog";
			}

			@GetMapping(path = "/about")
			String about(Model model) {
				return "about/about";
			}

			@GetMapping(path = "/contact")
			String contact(Model model) {
				return "contact/contact";
			}

			@GetMapping(path = { "/search/alpha", "/search/beta" })
			String search(Model model) {
				return "search/search";
			}

			@GetMapping(path = { "notification/alpha", "notification/beta" })
			String notification(Model model) {
				return "notification/notification";
			}

			@GetMapping(path = { "/report/alpha", "/report/beta" })
			String report(Model model) {
				return "report/report";
			}

			@GetMapping(path = { "/other" })
			String other(Model model) {
				return "other/other";
			}

			@DeleteMapping(path = { "/delete/{id}" })
			String delete(@PathVariable String id) {
				logger.info(LogMessage.format("id: %s%n", id));
				// Keep simple the approach
				return "delete/delete";
			}

			@DeleteMapping(path = { "/remove/{id}" })
			String remove(@PathVariable String id) {
				logger.info(LogMessage.format("id: %s%n", id));
				// Keep simple the approach
				return "remove/remove";
			}

			@PostMapping(path = { "/post" })
			String post() {
				// Keep simple the approach
				return "post/post";
			}

			@PostMapping(path = { "/save" })
			String save() {
				// Keep simple the approach
				return "save/save";
			}

			@PutMapping(path = { "/put" })
			String put() {
				// Keep simple the approach
				return "put/put";
			}

			@PutMapping(path = { "/update" })
			String update() {
				// Keep simple the approach
				return "update/update";
			}

			@PatchMapping(path = { "/patch/{id}" })
			String patch(@PathVariable String id) {
				logger.info(LogMessage.format("id: %s%n", id));
				// Keep simple the approach
				return "patch/patch";
			}

		}

	}

	/**
	 * @author Manuel Jordan
	 * @since 5.5
	 */
	@EnableWebMvc
	@EnableWebSecurity
	static class WebSecurityWithoutIgnoring extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication().withUser(PasswordEncodedUser.user()).withUser(PasswordEncodedUser.admin());
		}

		/**
		 * {@code antMatchers("/**").hasRole("OTHER")} really should be
		 * {@code antMatchers("/**").authenticated()}, but to test that really {@code /**}
		 * is being applied then {@code hasRole("OTHER")} is used.
		 *
		 * <p>
		 * DELETE, POST, PUT work with csrf, thus is mandatory use it or it can be
		 * ignored/avoid with {@code csrf().disable()}, otherwise those HTTP methods
		 * always fail with 403. Because is critical use csrf in production, the test
		 * methods for those HTTP methods use {@code .with(csrf())}
		 */
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http.authorizeRequests()
					.antMatchers("/something").hasRole("USER")
					.antMatchers("/home").authenticated()
					.antMatchers(HttpMethod.GET, "/search/alpha", "/search/beta").hasAnyRole("USER", "ADMIN", "OVERSIGHT")
					.antMatchers(HttpMethod.GET, "/notification/**", "/report/**").authenticated()
					.antMatchers(HttpMethod.POST).hasRole("ADMIN")//this approach only exists for 'antMatchers'
					.antMatchers(HttpMethod.PUT).hasRole("ADMIN")//this approach only exists for 'antMatchers'
					.antMatchers(HttpMethod.DELETE).hasRole("ADMIN")//this approach only exists for 'antMatchers'
					.antMatchers("/blog").permitAll()
					.antMatchers("/**").hasRole("OTHER")//latest line of defense, there is no ignore settings
														//should be 'authenticated()', but is used to be applied to '/other' and 'PATCH'
					.and()
				.formLogin();
			// @formatter:on
		}

		@Bean
		@Override
		public AuthenticationManager authenticationManagerBean() throws Exception {
			return super.authenticationManagerBean();
		}

		@Controller
		static class WebUniverseController {

			@GetMapping(path = "/home")
			String home(Model model) {
				return "home/home";
			}

			@GetMapping(path = "/something")
			String something(Model model) {
				return "something/something";
			}

			@GetMapping(path = "/blog")
			String blog(Model model) {
				return "blog/blog";
			}

			@GetMapping(path = "/about")
			String about(Model model) {
				return "about/about";
			}

			@GetMapping(path = "/contact")
			String contact(Model model) {
				return "contact/contact";
			}

			@GetMapping(path = { "/search/alpha", "/search/beta" })
			String search(Model model) {
				return "search/search";
			}

			@GetMapping(path = { "notification/alpha", "notification/beta" })
			String notification(Model model) {
				return "notification/notification";
			}

			@GetMapping(path = { "/report/alpha", "/report/beta" })
			String report(Model model) {
				return "report/report";
			}

			@GetMapping(path = { "/other" })
			String other(Model model) {
				return "other/other";
			}

			@DeleteMapping(path = { "/delete/{id}" })
			String delete(@PathVariable String id) {
				logger.info(LogMessage.format("id: %s%n", id));
				// Keep simple the approach
				return "delete/delete";
			}

			@DeleteMapping(path = { "/remove/{id}" })
			String remove(@PathVariable String id) {
				logger.info(LogMessage.format("id: %s%n", id));
				// Keep simple the approach
				return "remove/remove";
			}

			@PostMapping(path = { "/post" })
			String post() {
				// Keep simple the approach
				return "post/post";
			}

			@PostMapping(path = { "/save" })
			String save() {
				// Keep simple the approach
				return "save/save";
			}

			@PutMapping(path = { "/put" })
			String put() {
				// Keep simple the approach
				return "put/put";
			}

			@PutMapping(path = { "/update" })
			String update() {
				// Keep simple the approach
				return "update/update";
			}

			@PatchMapping(path = { "/patch/{id}" })
			String patch(@PathVariable String id) {
				logger.info(LogMessage.format("id: %s%n", id));
				// Keep simple the approach
				return "patch/patch";
			}

		}

	}

	/**
	 * @author Manuel Jordan
	 * @since 5.5
	 */
	@EnableWebMvc
	@EnableWebSecurity
	static class WebSecurityWithGlobalIgnoring extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication().withUser(PasswordEncodedUser.user()).withUser(PasswordEncodedUser.admin());
		}

		/**
		 * {@code antMatchers("/**").hasRole("OTHER")} really should be
		 * {@code antMatchers("/**").authenticated()}, but to test that really {@code /**}
		 * is being applied then {@code hasRole("OTHER")} is used. Nevertheless through
		 * {@code web.ignoring().antMatchers("/**")} is it is ignored.
		 *
		 * <p>
		 * DELETE, POST, PUT work with csrf, thus is mandatory use it or it can be
		 * ignored/avoid with {@code csrf().disable()}, otherwise those HTTP methods
		 * always fail with 403. Because is critical use csrf in production, the test
		 * methods for those HTTP methods use {@code .with(csrf())}
		 */
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http.authorizeRequests()
					.antMatchers("/something").hasRole("USER")
					.antMatchers("/home").authenticated()
					.antMatchers(HttpMethod.GET, "/search/alpha", "/search/beta").hasAnyRole("USER", "ADMIN", "OVERSIGHT")
					.antMatchers(HttpMethod.GET, "/notification/**", "/report/**").authenticated()
					.antMatchers(HttpMethod.POST).hasRole("ADMIN")//this approach only exists for 'antMatchers'
					.antMatchers(HttpMethod.PUT).hasRole("ADMIN")//this approach only exists for 'antMatchers'
					.antMatchers(HttpMethod.DELETE).hasRole("ADMIN")//this approach only exists for 'antMatchers'
					.antMatchers("/blog").permitAll()
					.antMatchers("/**").hasRole("OTHER")//to confirm that the role is completely ignored by 'web.ignoring()'
					.and()
				.formLogin();
			// @formatter:on
		}

		/**
		 * With these settings ({@code /**}, the settings on
		 * {@link #configure(HttpSecurity)} are completely ignored.
		 */
		@Override
		public void configure(WebSecurity web) throws Exception {
			// @formatter:off
			web.ignoring().antMatchers("/**")
						.antMatchers(HttpMethod.GET, "/**")// redundant, used for test output purposes
						.antMatchers(HttpMethod.PATCH); // this approach only exists for 'antMatchers'
			// @formatter:on
		}

		@Bean
		@Override
		public AuthenticationManager authenticationManagerBean() throws Exception {
			return super.authenticationManagerBean();
		}

		@Controller
		static class WebUniverseController {

			@GetMapping(path = "/home")
			String home(Model model) {
				return "home/home";
			}

			@GetMapping(path = "/something")
			String something(Model model) {
				return "something/something";
			}

			@GetMapping(path = "/blog")
			String blog(Model model) {
				return "blog/blog";
			}

			@GetMapping(path = "/about")
			String about(Model model) {
				return "about/about";
			}

			@GetMapping(path = "/contact")
			String contact(Model model) {
				return "contact/contact";
			}

			@GetMapping(path = { "/search/alpha", "/search/beta" })
			String search(Model model) {
				return "search/search";
			}

			@GetMapping(path = { "notification/alpha", "notification/beta" })
			String notification(Model model) {
				return "notification/notification";
			}

			@GetMapping(path = { "/report/alpha", "/report/beta" })
			String report(Model model) {
				return "report/report";
			}

			@GetMapping(path = { "/other" })
			String other(Model model) {
				return "other/other";
			}

			@DeleteMapping(path = { "/delete/{id}" })
			String delete(@PathVariable String id) {
				logger.info(LogMessage.format("id: %s%n", id));
				// Keep simple the approach
				return "delete/delete";
			}

			@DeleteMapping(path = { "/remove/{id}" })
			String remove(@PathVariable String id) {
				logger.info(LogMessage.format("id: %s%n", id));
				// Keep simple the approach
				return "remove/remove";
			}

			@PostMapping(path = { "/post" })
			String post() {
				// Keep simple the approach
				return "post/post";
			}

			@PostMapping(path = { "/save" })
			String save() {
				// Keep simple the approach
				return "save/save";
			}

			@PutMapping(path = { "/put" })
			String put() {
				// Keep simple the approach
				return "put/put";
			}

			@PutMapping(path = { "/update" })
			String update() {
				// Keep simple the approach
				return "update/update";
			}

			@PatchMapping(path = { "/patch/{id}" })
			String patch(@PathVariable String id) {
				logger.info(LogMessage.format("id: %s%n", id));
				// Keep simple the approach
				return "patch/patch";
			}

		}

	}

}
