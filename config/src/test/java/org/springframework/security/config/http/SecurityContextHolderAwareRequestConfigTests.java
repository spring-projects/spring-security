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

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.http.HttpHeaders;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rob Winch
 * @author Josh Cummings
 */
@ExtendWith({ SpringExtension.class, SpringTestContextExtension.class })
@SecurityTestExecutionListeners
public class SecurityContextHolderAwareRequestConfigTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/SecurityContextHolderAwareRequestConfigTests";

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mvc;

	@Test
	public void servletLoginWhenUsingDefaultConfigurationThenUsesSpringSecurity() throws Exception {
		this.spring.configLocations(this.xml("Simple")).autowire();
		// @formatter:off
		this.mvc.perform(get("/good-login"))
				.andExpect(status().isOk())
				.andExpect(content().string("user"));
		// @formatter:on
	}

	@Test
	public void servletAuthenticateWhenUsingDefaultConfigurationThenUsesSpringSecurity() throws Exception {
		this.spring.configLocations(this.xml("Simple")).autowire();
		// @formatter:off
		this.mvc.perform(get("/authenticate"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login"));
		// @formatter:on
	}

	@Test
	public void servletLogoutWhenUsingDefaultConfigurationThenUsesSpringSecurity() throws Exception {
		this.spring.configLocations(this.xml("Simple")).autowire();
		MvcResult result = this.mvc.perform(get("/good-login")).andReturn();
		MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
		assertThat(session).isNotNull();
		// @formatter:off
		result = this.mvc.perform(get("/do-logout").session(session))
				.andExpect(status().isOk())
				.andExpect(content().string(""))
				.andReturn();
		// @formatter:on
		session = (MockHttpSession) result.getRequest().getSession(false);
		assertThat(session).isNull();
	}

	@Test
	public void servletAuthenticateWhenUsingHttpBasicThenUsesSpringSecurity() throws Exception {
		this.spring.configLocations(this.xml("HttpBasic")).autowire();
		// @formatter:off
		this.mvc.perform(get("/authenticate"))
				.andExpect(status().isUnauthorized())
				.andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, containsString("discworld")));
		// @formatter:on
	}

	@Test
	public void servletAuthenticateWhenUsingFormLoginThenUsesSpringSecurity() throws Exception {
		this.spring.configLocations(this.xml("FormLogin")).autowire();
		// @formatter:off
		this.mvc.perform(get("/authenticate"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login"));
		// @formatter:on
	}

	@Test
	public void servletLoginWhenUsingMultipleHttpConfigsThenUsesSpringSecurity() throws Exception {
		this.spring.configLocations(this.xml("MultiHttp")).autowire();
		// @formatter:off
		this.mvc.perform(get("/good-login"))
				.andExpect(status().isOk())
				.andExpect(content().string("user"));
		this.mvc.perform(get("/v2/good-login"))
				.andExpect(status().isOk())
				.andExpect(content().string("user2"));
		// @formatter:on
	}

	@Test
	public void servletAuthenticateWhenUsingMultipleHttpConfigsThenUsesSpringSecurity() throws Exception {
		this.spring.configLocations(this.xml("MultiHttp")).autowire();
		// @formatter:off
		this.mvc.perform(get("/authenticate"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login"));
		this.mvc.perform(get("/v2/authenticate"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("http://localhost/login2"));
		// @formatter:on
	}

	@Test
	public void servletLogoutWhenUsingMultipleHttpConfigsThenUsesSpringSecurity() throws Exception {
		this.spring.configLocations(this.xml("MultiHttp")).autowire();
		MvcResult result = this.mvc.perform(get("/good-login")).andReturn();
		MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
		assertThat(session).isNotNull();
		// @formatter:off
		result = this.mvc.perform(get("/do-logout").session(session))
				.andExpect(status().isOk())
				.andExpect(content().string(""))
				.andReturn();
		// @formatter:on
		session = (MockHttpSession) result.getRequest().getSession(false);
		assertThat(session).isNotNull();
		// @formatter:off
		result = this.mvc.perform(get("/v2/good-login"))
				.andReturn();
		// @formatter:on
		session = (MockHttpSession) result.getRequest().getSession(false);
		assertThat(session).isNotNull();
		// @formatter:off
		result = this.mvc.perform(get("/v2/do-logout").session(session))
				.andExpect(status().isOk())
				.andExpect(content().string(""))
				.andReturn();
		// @formatter:on
		session = (MockHttpSession) result.getRequest().getSession(false);
		assertThat(session).isNull();
	}

	@Test
	public void servletLogoutWhenUsingCustomLogoutThenUsesSpringSecurity() throws Exception {
		this.spring.configLocations(this.xml("Logout")).autowire();
		this.mvc.perform(get("/authenticate"))
			.andExpect(status().isFound())
			.andExpect(redirectedUrl("http://localhost/signin"));
		// @formatter:off
		MvcResult result = this.mvc.perform(get("/good-login"))
				.andReturn();
		// @formatter:on
		MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
		assertThat(session).isNotNull();
		// @formatter:off
		result = this.mvc.perform(get("/do-logout").session(session))
				.andExpect(status().isOk())
				.andExpect(content().string(""))
				.andExpect(cookie().maxAge("JSESSIONID", 0))
				.andReturn();
		// @formatter:on
		session = (MockHttpSession) result.getRequest().getSession(false);
		assertThat(session).isNotNull();
	}

	/**
	 * SEC-2926: Role Prefix is set
	 */
	@Test
	@WithMockUser
	public void servletIsUserInRoleWhenUsingDefaultConfigThenRoleIsSet() throws Exception {
		this.spring.configLocations(this.xml("Simple")).autowire();
		// @formatter:off
		this.mvc.perform(get("/role"))
				.andExpect(content().string("true"));
		// @formatter:on
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	@RestController
	public static class ServletAuthenticatedController {

		@GetMapping("/v2/good-login")
		public String v2Login(HttpServletRequest request) throws ServletException {
			request.login("user2", "password2");
			return this.principal();
		}

		@GetMapping("/good-login")
		public String login(HttpServletRequest request) throws ServletException {
			request.login("user", "password");
			return this.principal();
		}

		@GetMapping("/v2/authenticate")
		public String v2Authenticate(HttpServletRequest request, HttpServletResponse response)
				throws IOException, ServletException {
			return this.authenticate(request, response);
		}

		@GetMapping("/authenticate")
		public String authenticate(HttpServletRequest request, HttpServletResponse response)
				throws IOException, ServletException {
			request.authenticate(response);
			return this.principal();
		}

		@GetMapping("/v2/do-logout")
		public String v2Logout(HttpServletRequest request) throws ServletException {
			return this.logout(request);
		}

		@GetMapping("/do-logout")
		public String logout(HttpServletRequest request) throws ServletException {
			request.logout();
			return this.principal();
		}

		@GetMapping("/role")
		public String role(HttpServletRequest request) {
			return String.valueOf(request.isUserInRole("USER"));
		}

		private String principal() {
			if (SecurityContextHolder.getContext().getAuthentication() != null) {
				return SecurityContextHolder.getContext().getAuthentication().getName();
			}
			return null;
		}

	}

}
