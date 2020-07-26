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

import java.security.Principal;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionFixationProtectionEvent;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Rob Winch
 * @author Josh Cummings
 */
public class NamespaceSessionManagementTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void authenticateWhenDefaultSessionManagementThenMatchesNamespace() throws Exception {
		this.spring.register(SessionManagementConfig.class, BasicController.class, UserDetailsServiceConfig.class)
				.autowire();

		MockHttpSession session = new MockHttpSession();
		String sessionId = session.getId();

		MvcResult result = this.mvc.perform(get("/auth").session(session).with(httpBasic("user", "password")))
				.andExpect(session()).andReturn();

		assertThat(result.getRequest().getSession(false).getId()).isNotEqualTo(sessionId);
	}

	@Test
	public void authenticateWhenUsingInvalidSessionUrlThenMatchesNamespace() throws Exception {
		this.spring.register(CustomSessionManagementConfig.class).autowire();

		this.mvc.perform(get("/auth").with(request -> {
			request.setRequestedSessionIdValid(false);
			request.setRequestedSessionId("id");
			return request;
		})).andExpect(redirectedUrl("/invalid-session"));
	}

	@Test
	public void authenticateWhenUsingExpiredUrlThenMatchesNamespace() throws Exception {
		this.spring.register(CustomSessionManagementConfig.class).autowire();

		MockHttpSession session = new MockHttpSession();
		SessionInformation sessionInformation = new SessionInformation(new Object(), session.getId(), new Date(0));
		sessionInformation.expireNow();
		SessionRegistry sessionRegistry = this.spring.getContext().getBean(SessionRegistry.class);
		when(sessionRegistry.getSessionInformation(session.getId())).thenReturn(sessionInformation);

		this.mvc.perform(get("/auth").session(session)).andExpect(redirectedUrl("/expired-session"));
	}

	@Test
	public void authenticateWhenUsingMaxSessionsThenMatchesNamespace() throws Exception {
		this.spring.register(CustomSessionManagementConfig.class, BasicController.class, UserDetailsServiceConfig.class)
				.autowire();

		this.mvc.perform(get("/auth").with(httpBasic("user", "password"))).andExpect(status().isOk());

		this.mvc.perform(get("/auth").with(httpBasic("user", "password")))
				.andExpect(redirectedUrl("/session-auth-error"));
	}

	@Test
	public void authenticateWhenUsingFailureUrlThenMatchesNamespace() throws Exception {
		this.spring.register(CustomSessionManagementConfig.class, BasicController.class, UserDetailsServiceConfig.class)
				.autowire();

		MockHttpServletRequest mock = spy(MockHttpServletRequest.class);
		mock.setSession(new MockHttpSession());
		when(mock.changeSessionId()).thenThrow(SessionAuthenticationException.class);
		mock.setMethod("GET");

		this.mvc.perform(get("/auth").with(request -> mock).with(httpBasic("user", "password")))
				.andExpect(redirectedUrl("/session-auth-error"));
	}

	@Test
	public void authenticateWhenUsingSessionRegistryThenMatchesNamespace() throws Exception {
		this.spring.register(CustomSessionManagementConfig.class, BasicController.class, UserDetailsServiceConfig.class)
				.autowire();

		SessionRegistry sessionRegistry = this.spring.getContext().getBean(SessionRegistry.class);

		this.mvc.perform(get("/auth").with(httpBasic("user", "password"))).andExpect(status().isOk());

		verify(sessionRegistry).registerNewSession(any(String.class), any(Object.class));
	}

	// gh-3371
	@Test
	public void authenticateWhenUsingCustomInvalidSessionStrategyThenMatchesNamespace() throws Exception {
		this.spring.register(InvalidSessionStrategyConfig.class).autowire();

		this.mvc.perform(get("/auth").with(request -> {
			request.setRequestedSessionIdValid(false);
			request.setRequestedSessionId("id");
			return request;
		})).andExpect(status().isOk());

		verifyBean(InvalidSessionStrategy.class).onInvalidSessionDetected(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void authenticateWhenUsingCustomSessionAuthenticationStrategyThenMatchesNamespace() throws Exception {
		this.spring.register(RefsSessionManagementConfig.class, BasicController.class, UserDetailsServiceConfig.class)
				.autowire();

		this.mvc.perform(get("/auth").with(httpBasic("user", "password"))).andExpect(status().isOk());

		verifyBean(SessionAuthenticationStrategy.class).onAuthentication(any(Authentication.class),
				any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void authenticateWhenNoSessionFixationProtectionThenMatchesNamespace() throws Exception {
		this.spring
				.register(SFPNoneSessionManagementConfig.class, BasicController.class, UserDetailsServiceConfig.class)
				.autowire();

		MockHttpSession givenSession = new MockHttpSession();
		String givenSessionId = givenSession.getId();
		MockHttpSession resultingSession = (MockHttpSession) this.mvc
				.perform(get("/auth").session(givenSession).with(httpBasic("user", "password")))
				.andExpect(status().isOk()).andReturn().getRequest().getSession(false);

		assertThat(givenSessionId).isEqualTo(resultingSession.getId());
	}

	@Test
	public void authenticateWhenMigrateSessionFixationProtectionThenMatchesNamespace() throws Exception {
		this.spring.register(SFPMigrateSessionManagementConfig.class, BasicController.class,
				UserDetailsServiceConfig.class).autowire();

		MockHttpSession givenSession = new MockHttpSession();
		String givenSessionId = givenSession.getId();
		givenSession.setAttribute("name", "value");

		MockHttpSession resultingSession = (MockHttpSession) this.mvc
				.perform(get("/auth").session(givenSession).with(httpBasic("user", "password")))
				.andExpect(status().isOk()).andReturn().getRequest().getSession(false);

		assertThat(givenSessionId).isNotEqualTo(resultingSession.getId());
		assertThat(resultingSession.getAttribute("name")).isEqualTo("value");
	}

	// SEC-2913
	@Test
	public void authenticateWhenUsingSessionFixationProtectionThenUsesNonNullEventPublisher() throws Exception {
		this.spring.register(SFPPostProcessedConfig.class, UserDetailsServiceConfig.class).autowire();

		this.mvc.perform(get("/auth").session(new MockHttpSession()).with(httpBasic("user", "password")))
				.andExpect(status().isNotFound());

		verifyBean(MockEventListener.class).onApplicationEvent(any(SessionFixationProtectionEvent.class));
	}

	@Test
	public void authenticateWhenNewSessionFixationProtectionThenMatchesNamespace() throws Exception {
		this.spring.register(SFPNewSessionSessionManagementConfig.class, UserDetailsServiceConfig.class).autowire();

		MockHttpSession givenSession = new MockHttpSession();
		String givenSessionId = givenSession.getId();
		givenSession.setAttribute("name", "value");

		MockHttpSession resultingSession = (MockHttpSession) this.mvc
				.perform(get("/auth").session(givenSession).with(httpBasic("user", "password")))
				.andExpect(status().isNotFound()).andReturn().getRequest().getSession(false);

		assertThat(givenSessionId).isNotEqualTo(resultingSession.getId());
		assertThat(resultingSession.getAttribute("name")).isNull();
	}

	private <T> T verifyBean(Class<T> clazz) {
		return verify(this.spring.getContext().getBean(clazz));
	}

	private static SessionResultMatcher session() {
		return new SessionResultMatcher();
	}

	@EnableWebSecurity
	static class SessionManagementConfig extends WebSecurityConfigurerAdapter {

	}

	@EnableWebSecurity
	static class CustomSessionManagementConfig extends WebSecurityConfigurerAdapter {

		SessionRegistry sessionRegistry = spy(SessionRegistryImpl.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.httpBasic()
					.and()
				.sessionManagement()
					.invalidSessionUrl("/invalid-session") // session-management@invalid-session-url
					.sessionAuthenticationErrorUrl("/session-auth-error") // session-management@session-authentication-error-url
					.maximumSessions(1) // session-management/concurrency-control@max-sessions
						.maxSessionsPreventsLogin(true) // session-management/concurrency-control@error-if-maximum-exceeded
						.expiredUrl("/expired-session") // session-management/concurrency-control@expired-url
						.sessionRegistry(sessionRegistry()); // session-management/concurrency-control@session-registry-ref
			// @formatter:on
		}

		@Bean
		SessionRegistry sessionRegistry() {
			return this.sessionRegistry;
		}

	}

	@EnableWebSecurity
	static class InvalidSessionStrategyConfig extends WebSecurityConfigurerAdapter {

		InvalidSessionStrategy invalidSessionStrategy = mock(InvalidSessionStrategy.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement()
					.invalidSessionStrategy(invalidSessionStrategy());
			// @formatter:on
		}

		@Bean
		InvalidSessionStrategy invalidSessionStrategy() {
			return this.invalidSessionStrategy;
		}

	}

	@EnableWebSecurity
	static class RefsSessionManagementConfig extends WebSecurityConfigurerAdapter {

		SessionAuthenticationStrategy sessionAuthenticationStrategy = mock(SessionAuthenticationStrategy.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement()
					.sessionAuthenticationStrategy(sessionAuthenticationStrategy()) // session-management@session-authentication-strategy-ref
					.and()
				.httpBasic();
			// @formatter:on
		}

		@Bean
		SessionAuthenticationStrategy sessionAuthenticationStrategy() {
			return this.sessionAuthenticationStrategy;
		}

	}

	@EnableWebSecurity
	static class SFPNoneSessionManagementConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement()
					.sessionAuthenticationStrategy(new NullAuthenticatedSessionStrategy())
					.and()
				.httpBasic();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class SFPMigrateSessionManagementConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement()
					.and()
				.httpBasic();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class SFPPostProcessedConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement()
					.and()
				.httpBasic();
			// @formatter:on
		}

		@Bean
		public MockEventListener eventListener() {
			return spy(new MockEventListener());
		}

	}

	@EnableWebSecurity
	static class SFPNewSessionSessionManagementConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement()
					.sessionFixation().newSession()
					.and()
				.httpBasic();
			// @formatter:on
		}

	}

	static class MockEventListener implements ApplicationListener<SessionFixationProtectionEvent> {

		List<SessionFixationProtectionEvent> events = new ArrayList<>();

		@Override
		public void onApplicationEvent(SessionFixationProtectionEvent event) {
			this.events.add(event);
		}

	}

	@Configuration
	static class UserDetailsServiceConfig {

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(
			// @formatter:off
					User.withDefaultPasswordEncoder()
							.username("user")
							.password("password")
							.roles("USER")
							.build());
					// @formatter:on
		}

	}

	@RestController
	static class BasicController {

		@GetMapping("/")
		public String ok() {
			return "ok";
		}

		@GetMapping("/auth")
		public String auth(Principal principal) {
			return principal.getName();
		}

	}

	private static class SessionResultMatcher implements ResultMatcher {

		private String id;

		private Boolean valid;

		private Boolean exists = true;

		public ResultMatcher exists(boolean exists) {
			this.exists = exists;
			return this;
		}

		public ResultMatcher valid(boolean valid) {
			this.valid = valid;
			return this.exists(true);
		}

		public ResultMatcher id(String id) {
			this.id = id;
			return this.exists(true);
		}

		@Override
		public void match(MvcResult result) {
			if (!this.exists) {
				assertThat(result.getRequest().getSession(false)).isNull();
				return;
			}

			assertThat(result.getRequest().getSession(false)).isNotNull();

			MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);

			if (this.valid != null) {
				if (this.valid) {
					assertThat(session.isInvalid()).isFalse();
				}
				else {
					assertThat(session.isInvalid()).isTrue();
				}
			}

			if (this.id != null) {
				assertThat(session.getId()).isEqualTo(this.id);
			}
		}

	}

}
