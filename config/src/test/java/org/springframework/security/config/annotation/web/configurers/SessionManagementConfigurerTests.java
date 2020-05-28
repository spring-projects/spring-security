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

import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.HttpSessionDestroyedEvent;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link SessionManagementConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 */
public class SessionManagementConfigurerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void sessionManagementWhenConfiguredThenDoesNotOverrideRequestCache() throws Exception {
		SessionManagementRequestCacheConfig.REQUEST_CACHE = mock(RequestCache.class);
		this.spring.register(SessionManagementRequestCacheConfig.class).autowire();

		this.mvc.perform(get("/"));

		verify(SessionManagementRequestCacheConfig.REQUEST_CACHE)
				.getMatchingRequest(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@EnableWebSecurity
	static class SessionManagementRequestCacheConfig extends WebSecurityConfigurerAdapter {
		static RequestCache REQUEST_CACHE;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestCache()
					.requestCache(REQUEST_CACHE)
					.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			// @formatter:on
		}
	}

	@Test
	public void sessionManagementWhenConfiguredThenDoesNotOverrideSecurityContextRepository() throws Exception {
		SessionManagementSecurityContextRepositoryConfig.SECURITY_CONTEXT_REPO = mock(SecurityContextRepository.class);
		when(SessionManagementSecurityContextRepositoryConfig.SECURITY_CONTEXT_REPO.loadContext(any(HttpRequestResponseHolder.class)))
				.thenReturn(mock(SecurityContext.class));
		this.spring.register(SessionManagementSecurityContextRepositoryConfig.class).autowire();

		this.mvc.perform(get("/"));

		verify(SessionManagementSecurityContextRepositoryConfig.SECURITY_CONTEXT_REPO).saveContext(
				any(SecurityContext.class),
				any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@EnableWebSecurity
	static class SessionManagementSecurityContextRepositoryConfig extends WebSecurityConfigurerAdapter {
		static SecurityContextRepository SECURITY_CONTEXT_REPO;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.securityContext()
					.securityContextRepository(SECURITY_CONTEXT_REPO)
					.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			// @formatter:on
		}
	}

	@Test
	public void sessionManagementWhenInvokedTwiceThenUsesOriginalSessionCreationPolicy() throws Exception {
		this.spring.register(InvokeTwiceDoesNotOverride.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/"))
				.andReturn();
		HttpSession session = mvcResult.getRequest().getSession(false);

		assertThat(session).isNull();
	}

	@EnableWebSecurity
	static class InvokeTwiceDoesNotOverride extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
					.and()
				.sessionManagement();
			// @formatter:on
		}
	}

	// SEC-2137
	@Test
	public void getWhenSessionFixationDisabledAndConcurrencyControlEnabledThenSessionIsNotInvalidated()
			throws Exception {
		this.spring.register(DisableSessionFixationEnableConcurrencyControlConfig.class).autowire();
		MockHttpSession session = new MockHttpSession();
		String sessionId = session.getId();

		MvcResult mvcResult = this.mvc.perform(get("/")
				.with(httpBasic("user", "password"))
				.session(session))
				.andExpect(status().isNotFound())
				.andReturn();

		assertThat(mvcResult.getRequest().getSession().getId()).isEqualTo(sessionId);
	}

	@EnableWebSecurity
	static class DisableSessionFixationEnableConcurrencyControlConfig extends WebSecurityConfigurerAdapter {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.sessionManagement()
					.sessionFixation().none()
					.maximumSessions(1);
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}
	}

	@Test
	public void authenticateWhenNewSessionFixationProtectionInLambdaThenCreatesNewSession() throws Exception {
		this.spring.register(SFPNewSessionInLambdaConfig.class).autowire();

		MockHttpSession givenSession = new MockHttpSession();
		String givenSessionId = givenSession.getId();
		givenSession.setAttribute("name", "value");

		MockHttpSession resultingSession = (MockHttpSession)
				this.mvc.perform(get("/auth")
						.session(givenSession)
						.with(httpBasic("user", "password")))
						.andExpect(status().isNotFound())
						.andReturn().getRequest().getSession(false);

		assertThat(givenSessionId).isNotEqualTo(resultingSession.getId());
		assertThat(resultingSession.getAttribute("name")).isNull();
	}

	@EnableWebSecurity
	static class SFPNewSessionInLambdaConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement(sessionManagement ->
					sessionManagement
						.sessionFixation(sessionFixation ->
							sessionFixation.newSession()
						)
				)
				.httpBasic(withDefaults());
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}
	}

	@Test
	public void loginWhenUserLoggedInAndMaxSessionsIsOneThenLoginPrevented() throws Exception {
		this.spring.register(ConcurrencyControlConfig.class).autowire();

		this.mvc.perform(post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password"));

		this.mvc.perform(post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?error"));
	}

	@Test
	public void loginWhenUserSessionExpiredAndMaxSessionsIsOneThenLoggedIn() throws Exception {
		this.spring.register(ConcurrencyControlConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password"))
				.andReturn();
		HttpSession authenticatedSession = mvcResult.getRequest().getSession();
		this.spring.getContext().publishEvent(new HttpSessionDestroyedEvent(authenticatedSession));

		this.mvc.perform(post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/"));
	}

	@EnableWebSecurity
	static class ConcurrencyControlConfig extends WebSecurityConfigurerAdapter {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.and()
				.sessionManagement()
					.maximumSessions(1)
					.maxSessionsPreventsLogin(true);
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}
	}

	@Test
	public void loginWhenUserLoggedInAndMaxSessionsOneInLambdaThenLoginPrevented() throws Exception {
		this.spring.register(ConcurrencyControlInLambdaConfig.class).autowire();

		this.mvc.perform(post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password"));

		this.mvc.perform(post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?error"));
	}

	@EnableWebSecurity
	static class ConcurrencyControlInLambdaConfig extends WebSecurityConfigurerAdapter {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin(withDefaults())
				.sessionManagement(sessionManagement ->
					sessionManagement
						.sessionConcurrency(sessionConcurrency ->
							sessionConcurrency
								.maximumSessions(1)
								.maxSessionsPreventsLogin(true)
						)
				);
			// @formatter:on
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user());
			// @formatter:on
		}
	}

	@Test
	public void requestWhenSessionCreationPolicyStateLessInLambdaThenNoSessionCreated() throws Exception {
		this.spring.register(SessionCreationPolicyStateLessInLambdaConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/"))
				.andReturn();
		HttpSession session = mvcResult.getRequest().getSession(false);

		assertThat(session).isNull();
	}

	@EnableWebSecurity
	static class SessionCreationPolicyStateLessInLambdaConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement(sessionManagement ->
					sessionManagement
						.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				);
			// @formatter:on
		}
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnSessionManagementFilter() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();

		verify(ObjectPostProcessorConfig.objectPostProcessor)
				.postProcess(any(SessionManagementFilter.class));
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnConcurrentSessionFilter() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();

		verify(ObjectPostProcessorConfig.objectPostProcessor)
				.postProcess(any(ConcurrentSessionFilter.class));
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnConcurrentSessionControlAuthenticationStrategy() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();

		verify(ObjectPostProcessorConfig.objectPostProcessor)
				.postProcess(any(ConcurrentSessionControlAuthenticationStrategy.class));
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnCompositeSessionAuthenticationStrategy() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();

		verify(ObjectPostProcessorConfig.objectPostProcessor)
				.postProcess(any(CompositeSessionAuthenticationStrategy.class));
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnRegisterSessionAuthenticationStrategy() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();

		verify(ObjectPostProcessorConfig.objectPostProcessor)
				.postProcess(any(RegisterSessionAuthenticationStrategy.class));
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnChangeSessionIdAuthenticationStrategy() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();

		verify(ObjectPostProcessorConfig.objectPostProcessor)
				.postProcess(any(ChangeSessionIdAuthenticationStrategy.class));
	}

	@EnableWebSecurity
	static class ObjectPostProcessorConfig extends WebSecurityConfigurerAdapter {
		static ObjectPostProcessor<Object> objectPostProcessor;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement()
					.maximumSessions(1);
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

	@Test
	public void getWhenAnonymousRequestAndTrustResolverSharedObjectReturnsAnonymousFalseThenSessionIsSaved()
			throws Exception {
		SharedTrustResolverConfig.TR = mock(AuthenticationTrustResolver.class);
		when(SharedTrustResolverConfig.TR.isAnonymous(any())).thenReturn(false);
		this.spring.register(SharedTrustResolverConfig.class).autowire();

		MvcResult mvcResult = this.mvc.perform(get("/"))
				.andReturn();

		assertThat(mvcResult.getRequest().getSession(false)).isNotNull();
	}

	@EnableWebSecurity
	static class SharedTrustResolverConfig extends WebSecurityConfigurerAdapter {
		static AuthenticationTrustResolver TR;

		@Override
		protected void configure(HttpSecurity http) {
			// @formatter:off
			http
				.setSharedObject(AuthenticationTrustResolver.class, TR);
			// @formatter:on
		}
	}

	@Test
	public void whenOneSessionRegistryBeanThenUseIt() throws Exception {
		SessionRegistryOneBeanConfig.SESSION_REGISTRY = mock(SessionRegistry.class);
		this.spring.register(SessionRegistryOneBeanConfig.class).autowire();

		MockHttpSession session = new MockHttpSession(this.spring.getContext().getServletContext());
		this.mvc.perform(get("/").session(session));

		verify(SessionRegistryOneBeanConfig.SESSION_REGISTRY)
				.getSessionInformation(session.getId());
	}

	@Test
	public void whenTwoSessionRegistryBeansThenUseNeither() throws Exception {
		SessionRegistryTwoBeansConfig.SESSION_REGISTRY_ONE = mock(SessionRegistry.class);
		SessionRegistryTwoBeansConfig.SESSION_REGISTRY_TWO = mock(SessionRegistry.class);
		this.spring.register(SessionRegistryTwoBeansConfig.class).autowire();

		MockHttpSession session = new MockHttpSession(this.spring.getContext().getServletContext());
		this.mvc.perform(get("/").session(session));

		verifyNoInteractions(SessionRegistryTwoBeansConfig.SESSION_REGISTRY_ONE);
		verifyNoInteractions(SessionRegistryTwoBeansConfig.SESSION_REGISTRY_TWO);
	}

	@EnableWebSecurity
	static class SessionRegistryOneBeanConfig extends WebSecurityConfigurerAdapter {
		private static SessionRegistry SESSION_REGISTRY;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement()
				.maximumSessions(1);
			// @formatter:on
		}

		@Bean
		public SessionRegistry sessionRegistry() {
			return SESSION_REGISTRY;
		}
	}

	@EnableWebSecurity
	static class SessionRegistryTwoBeansConfig extends WebSecurityConfigurerAdapter {
		private static SessionRegistry SESSION_REGISTRY_ONE;

		private static SessionRegistry SESSION_REGISTRY_TWO;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement()
				.maximumSessions(1);
			// @formatter:on
		}

		@Bean
		public SessionRegistry sessionRegistryOne() {
			return SESSION_REGISTRY_ONE;
		}

		@Bean
		public SessionRegistry sessionRegistryTwo() {
			return SESSION_REGISTRY_TWO;
		}
	}
}
