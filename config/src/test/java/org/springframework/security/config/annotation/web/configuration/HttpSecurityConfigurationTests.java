/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.config.annotation.web.configuration;

import com.google.common.net.HttpHeaders;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.concurrent.Callable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link HttpSecurityConfiguration}.
 *
 * @author Eleftheria Stein
 */
public class HttpSecurityConfigurationTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private MockMvc mockMvc;

	@Test
	public void postWhenDefaultFilterChainBeanThenRespondsWithForbidden() throws Exception {
		this.spring.register(DefaultWithFilterChainConfig.class).autowire();

		this.mockMvc.perform(post("/")).andExpect(status().isForbidden());
	}

	@Test
	public void getWhenDefaultFilterChainBeanThenDefaultHeadersInResponse() throws Exception {
		this.spring.register(DefaultWithFilterChainConfig.class).autowire();

		MvcResult mvcResult = this.mockMvc.perform(get("/").secure(true))
				.andExpect(header().string(HttpHeaders.X_CONTENT_TYPE_OPTIONS, "nosniff"))
				.andExpect(header().string(HttpHeaders.X_FRAME_OPTIONS,
						XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY.name()))
				.andExpect(
						header().string(HttpHeaders.STRICT_TRANSPORT_SECURITY, "max-age=31536000 ; includeSubDomains"))
				.andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate"))
				.andExpect(header().string(HttpHeaders.EXPIRES, "0"))
				.andExpect(header().string(HttpHeaders.PRAGMA, "no-cache"))
				.andExpect(header().string(HttpHeaders.X_XSS_PROTECTION, "1; mode=block")).andReturn();
		assertThat(mvcResult.getResponse().getHeaderNames()).containsExactlyInAnyOrder(
				HttpHeaders.X_CONTENT_TYPE_OPTIONS, HttpHeaders.X_FRAME_OPTIONS, HttpHeaders.STRICT_TRANSPORT_SECURITY,
				HttpHeaders.CACHE_CONTROL, HttpHeaders.EXPIRES, HttpHeaders.PRAGMA, HttpHeaders.X_XSS_PROTECTION);
	}

	@Test
	public void logoutWhenDefaultFilterChainBeanThenCreatesDefaultLogoutEndpoint() throws Exception {
		this.spring.register(DefaultWithFilterChainConfig.class).autowire();

		this.mockMvc.perform(post("/logout").with(csrf())).andExpect(redirectedUrl("/login?logout"));
	}

	@Test
	public void loadConfigWhenDefaultConfigThenWebAsyncManagerIntegrationFilterAdded() throws Exception {
		this.spring.register(DefaultWithFilterChainConfig.class, NameController.class).autowire();

		MvcResult mvcResult = this.mockMvc.perform(get("/name").with(user("Bob"))).andExpect(request().asyncStarted())
				.andReturn();

		this.mockMvc.perform(asyncDispatch(mvcResult)).andExpect(status().isOk()).andExpect(content().string("Bob"));
	}

	@RestController
	static class NameController {

		@GetMapping("/name")
		public Callable<String> name() {
			return () -> SecurityContextHolder.getContext().getAuthentication().getName();
		}

	}

	@EnableWebSecurity
	static class DefaultWithFilterChainConfig {

		@Bean
		public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			return http.build();
		}

	}

	@Test
	public void getWhenDefaultFilterChainBeanThenAnonymousPermitted() throws Exception {
		this.spring.register(AuthorizeRequestsConfig.class, UserDetailsConfig.class, BaseController.class).autowire();

		this.mockMvc.perform(get("/")).andExpect(status().isOk());
	}

	@EnableWebSecurity
	static class AuthorizeRequestsConfig {

		@Bean
		public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			return http.authorizeRequests(authorize -> authorize.anyRequest().permitAll()).build();
		}

	}

	@Test
	public void authenticateWhenDefaultFilterChainBeanThenSessionIdChanges() throws Exception {
		this.spring.register(SecurityEnabledConfig.class, UserDetailsConfig.class).autowire();

		MockHttpSession session = new MockHttpSession();
		String sessionId = session.getId();

		MvcResult result = this.mockMvc.perform(
				post("/login").param("username", "user").param("password", "password").session(session).with(csrf()))
				.andReturn();

		assertThat(result.getRequest().getSession(false).getId()).isNotEqualTo(sessionId);
	}

	@Test
	public void authenticateWhenDefaultFilterChainBeanThenRedirectsToSavedRequest() throws Exception {
		this.spring.register(SecurityEnabledConfig.class, UserDetailsConfig.class).autowire();

		MockHttpSession session = (MockHttpSession) this.mockMvc.perform(get("/messages")).andReturn().getRequest()
				.getSession();

		this.mockMvc.perform(
				post("/login").param("username", "user").param("password", "password").session(session).with(csrf()))
				.andExpect(redirectedUrl("http://localhost/messages"));
	}

	@Test
	public void authenticateWhenDefaultFilterChainBeanThenRolePrefixIsSet() throws Exception {
		this.spring.register(SecurityEnabledConfig.class, UserDetailsConfig.class, UserController.class).autowire();

		this.mockMvc
				.perform(get("/user")
						.with(authentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"))))
				.andExpect(status().isOk());
	}

	@Test
	public void loginWhenUsingDefaultsThenDefaultLoginPageGenerated() throws Exception {
		this.spring.register(SecurityEnabledConfig.class).autowire();

		this.mockMvc.perform(get("/login")).andExpect(status().isOk());
	}

	@EnableWebSecurity
	static class SecurityEnabledConfig {

		@Bean
		public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			return http.authorizeRequests(authorize -> authorize.anyRequest().authenticated()).formLogin(withDefaults())
					.build();
		}

	}

	@Configuration
	static class UserDetailsConfig {

		@Bean
		public UserDetailsService userDetailsService() {
			UserDetails user = User.withDefaultPasswordEncoder().username("user").password("password").roles("USER")
					.build();
			return new InMemoryUserDetailsManager(user);
		}

	}

	@RestController
	static class BaseController {

		@GetMapping("/")
		public void index() {
		}

	}

	@RestController
	static class UserController {

		@GetMapping("/user")
		public void user(HttpServletRequest request) {
			if (!request.isUserInRole("USER")) {
				throw new AccessDeniedException("This resource is only available to users");
			}
		}

	}

}
