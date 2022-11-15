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

import java.io.IOException;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.TestDeferredSecurityContext;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.HttpSessionDestroyedEvent;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.WebUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link SessionManagementConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension.class)
public class SessionManagementConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void sessionManagementWhenConfiguredThenDoesNotOverrideRequestCache() throws Exception {
		SessionManagementRequestCacheConfig.REQUEST_CACHE = mock(RequestCache.class);
		this.spring.register(SessionManagementRequestCacheConfig.class).autowire();
		this.mvc.perform(get("/"));
		verify(SessionManagementRequestCacheConfig.REQUEST_CACHE).getMatchingRequest(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void sessionManagementWhenConfiguredThenDoesNotOverrideSecurityContextRepository() throws Exception {
		SessionManagementSecurityContextRepositoryConfig.SECURITY_CONTEXT_REPO = mock(SecurityContextRepository.class);
		given(SessionManagementSecurityContextRepositoryConfig.SECURITY_CONTEXT_REPO
				.loadDeferredContext(any(HttpServletRequest.class)))
						.willReturn(new TestDeferredSecurityContext(mock(SecurityContext.class), false));
		this.spring.register(SessionManagementSecurityContextRepositoryConfig.class).autowire();
		this.mvc.perform(get("/"));
	}

	@Test
	public void sessionManagementWhenInvokedTwiceThenUsesOriginalSessionCreationPolicy() throws Exception {
		this.spring.register(InvokeTwiceDoesNotOverride.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/")).andReturn();
		HttpSession session = mvcResult.getRequest().getSession(false);
		assertThat(session).isNull();
	}

	// SEC-2137
	@Test
	public void getWhenSessionFixationDisabledAndConcurrencyControlEnabledThenSessionIsNotInvalidated()
			throws Exception {
		this.spring.register(DisableSessionFixationEnableConcurrencyControlConfig.class).autowire();
		MockHttpSession session = new MockHttpSession();
		String sessionId = session.getId();
		// @formatter:off
		MockHttpServletRequestBuilder request = get("/")
				.with(httpBasic("user", "password"))
				.session(session);
		MvcResult mvcResult = this.mvc.perform(request)
				.andExpect(status().isNotFound())
				.andReturn();
		// @formatter:on
		assertThat(mvcResult.getRequest().getSession().getId()).isEqualTo(sessionId);
	}

	@Test
	public void authenticateWhenNewSessionFixationProtectionInLambdaThenCreatesNewSession() throws Exception {
		this.spring.register(SFPNewSessionInLambdaConfig.class).autowire();
		MockHttpSession givenSession = new MockHttpSession();
		String givenSessionId = givenSession.getId();
		givenSession.setAttribute("name", "value");
		// @formatter:off
		MockHttpServletRequestBuilder request = get("/auth")
				.session(givenSession)
				.with(httpBasic("user", "password"));
		MockHttpSession resultingSession = (MockHttpSession) this.mvc.perform(request)
				.andExpect(status().isNotFound())
				.andReturn()
				.getRequest()
				.getSession(false);
		// @formatter:on
		assertThat(givenSessionId).isNotEqualTo(resultingSession.getId());
		assertThat(resultingSession.getAttribute("name")).isNull();
	}

	@Test
	public void loginWhenUserLoggedInAndMaxSessionsIsOneThenLoginPrevented() throws Exception {
		this.spring.register(ConcurrencyControlConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder firstRequest = post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password");
		this.mvc.perform(firstRequest);
		MockHttpServletRequestBuilder secondRequest = post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password");
		this.mvc.perform(secondRequest)
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?error"));
		// @formatter:on
	}

	@Test
	public void loginWhenUserSessionExpiredAndMaxSessionsIsOneThenLoggedIn() throws Exception {
		this.spring.register(ConcurrencyControlConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder firstRequest = post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password");
		MvcResult mvcResult = this.mvc.perform(firstRequest)
				.andReturn();
		// @formatter:on
		HttpSession authenticatedSession = mvcResult.getRequest().getSession();
		this.spring.getContext().publishEvent(new HttpSessionDestroyedEvent(authenticatedSession));
		// @formatter:off
		MockHttpServletRequestBuilder secondRequest = post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password");
		this.mvc.perform(secondRequest)
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/"));
		// @formatter:on
	}

	@Test
	public void loginWhenUserLoggedInAndMaxSessionsOneInLambdaThenLoginPrevented() throws Exception {
		this.spring.register(ConcurrencyControlInLambdaConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder firstRequest = post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password");
		// @formatter:on
		this.mvc.perform(firstRequest);
		// @formatter:off
		MockHttpServletRequestBuilder secondRequest = post("/login")
				.with(csrf())
				.param("username", "user")
				.param("password", "password");
		this.mvc.perform(secondRequest)
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/login?error"));
		// @formatter:on
	}

	@Test
	public void requestWhenSessionCreationPolicyStateLessInLambdaThenNoSessionCreated() throws Exception {
		this.spring.register(SessionCreationPolicyStateLessInLambdaConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/")).andReturn();
		HttpSession session = mvcResult.getRequest().getSession(false);
		assertThat(session).isNull();
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnSessionManagementFilter() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(SessionManagementFilter.class));
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnConcurrentSessionFilter() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(ConcurrentSessionFilter.class));
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

	@Test
	public void getWhenAnonymousRequestAndTrustResolverSharedObjectReturnsAnonymousFalseThenSessionIsSaved()
			throws Exception {
		SharedTrustResolverConfig.TR = mock(AuthenticationTrustResolver.class);
		given(SharedTrustResolverConfig.TR.isAnonymous(any())).willReturn(false);
		this.spring.register(SharedTrustResolverConfig.class).autowire();
		MvcResult mvcResult = this.mvc.perform(get("/")).andReturn();
		assertThat(mvcResult.getRequest().getSession(false)).isNotNull();
	}

	@Test
	public void whenOneSessionRegistryBeanThenUseIt() throws Exception {
		SessionRegistryOneBeanConfig.SESSION_REGISTRY = mock(SessionRegistry.class);
		this.spring.register(SessionRegistryOneBeanConfig.class).autowire();
		MockHttpSession session = new MockHttpSession(this.spring.getContext().getServletContext());
		this.mvc.perform(get("/").session(session));
		verify(SessionRegistryOneBeanConfig.SESSION_REGISTRY).getSessionInformation(session.getId());
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

	@Test
	public void whenEnableSessionUrlRewritingTrueThenEncodeNotInvoked() throws Exception {
		this.spring.register(EnableUrlRewriteConfig.class).autowire();
		// @formatter:off
		this.mvc = MockMvcBuilders.webAppContextSetup(this.spring.getContext())
			.addFilters((request, response, chain) -> {
				HttpServletResponse responseToSpy = spy((HttpServletResponse) response);
				chain.doFilter(request, responseToSpy);
				verify(responseToSpy, atLeastOnce()).encodeRedirectURL(any());
				verify(responseToSpy, atLeastOnce()).encodeURL(any());
			})
			.apply(springSecurity())
			.build();
		// @formatter:on

		this.mvc.perform(get("/")).andExpect(content().string("encoded"));
	}

	@Test
	public void whenDefaultThenEncodeNotInvoked() throws Exception {
		this.spring.register(DefaultUrlRewriteConfig.class).autowire();
		// @formatter:off
		this.mvc = MockMvcBuilders.webAppContextSetup(this.spring.getContext())
			.addFilters((request, response, chain) -> {
				HttpServletResponse responseToSpy = spy((HttpServletResponse) response);
				chain.doFilter(request, responseToSpy);
				verify(responseToSpy, never()).encodeRedirectURL(any());
				verify(responseToSpy, never()).encodeURL(any());
			})
			.apply(springSecurity())
			.build();
		// @formatter:on

		this.mvc.perform(get("/")).andExpect(content().string("encoded"));
	}

	@Test
	public void loginWhenSessionCreationPolicyStatelessThenSecurityContextIsAvailableInRequestAttributes()
			throws Exception {
		this.spring.register(HttpBasicSessionCreationPolicyStatelessConfig.class).autowire();
		// @formatter:off
		MvcResult mvcResult = this.mvc.perform(get("/").with(httpBasic("user", "password")))
				.andExpect(status().isOk())
				.andReturn();
		// @formatter:on
		HttpSession session = mvcResult.getRequest().getSession(false);
		assertThat(session).isNull();
		SecurityContext securityContext = (SecurityContext) mvcResult.getRequest()
				.getAttribute(RequestAttributeSecurityContextRepository.DEFAULT_REQUEST_ATTR_NAME);
		assertThat(securityContext).isNotNull();
	}

	/**
	 * This ensures that if an ErrorDispatch occurs, then the SecurityContextRepository
	 * defaulted by SessionManagementConfigurer is correct (looks at both Session and
	 * Request Attributes).
	 * @throws Exception
	 */
	@Test
	public void gh12070WhenErrorDispatchSecurityContextRepositoryWorks() throws Exception {
		Filter errorDispatchFilter = new Filter() {
			@Override
			public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
					throws IOException, ServletException {
				try {
					chain.doFilter(request, response);
				}
				catch (ServletException ex) {
					if (request.getDispatcherType() == DispatcherType.ERROR) {
						throw ex;
					}
					MockHttpServletRequest httpRequest = WebUtils.getNativeRequest(request,
							MockHttpServletRequest.class);
					httpRequest.setDispatcherType(DispatcherType.ERROR);
					// necessary to prevent HttpBasicFilter from invoking again
					httpRequest.setAttribute(WebUtils.ERROR_REQUEST_URI_ATTRIBUTE, "/error");
					httpRequest.setRequestURI("/error");
					MockFilterChain mockChain = (MockFilterChain) chain;
					mockChain.reset();
					mockChain.doFilter(httpRequest, response);
				}
			}
		};
		this.spring.addFilter(errorDispatchFilter).register(Gh12070IssueConfig.class).autowire();

		// @formatter:off
		this.mvc.perform(get("/500").with(httpBasic("user", "password")))
				.andExpect(status().isInternalServerError());
		// @formatter:on
	}

	@Configuration
	@EnableWebSecurity
	static class Gh12070IssueConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((authorize) -> authorize
					.anyRequest().authenticated()
				)
				.httpBasic(Customizer.withDefaults())
				.formLogin(Customizer.withDefaults());
			return http.build();
			// @formatter:on
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

		@RestController
		static class ErrorController {

			@GetMapping("/500")
			String error() throws ServletException {
				throw new ServletException("Error");
			}

			@GetMapping("/error")
			ResponseEntity<String> errorHandler() {
				return new ResponseEntity<>("error", HttpStatus.INTERNAL_SERVER_ERROR);
			}

		}

	}

	@Configuration
	@EnableWebSecurity
	static class SessionManagementRequestCacheConfig {

		static RequestCache REQUEST_CACHE;

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestCache()
					.requestCache(REQUEST_CACHE)
					.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class SessionManagementSecurityContextRepositoryConfig {

		static SecurityContextRepository SECURITY_CONTEXT_REPO;

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.securityContext()
					.securityContextRepository(SECURITY_CONTEXT_REPO)
					.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class InvokeTwiceDoesNotOverride {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
					.and()
				.sessionManagement();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DisableSessionFixationEnableConcurrencyControlConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.httpBasic()
					.and()
				.sessionManagement()
					.sessionFixation().none()
					.maximumSessions(1);
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
	static class SFPNewSessionInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement((sessionManagement) ->
					sessionManagement
						.requireExplicitAuthenticationStrategy(false)
						.sessionFixation((sessionFixation) ->
							sessionFixation.newSession()
						)
				)
				.httpBasic(withDefaults());
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
	static class ConcurrencyControlConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin()
					.and()
				.sessionManagement()
					.maximumSessions(1)
					.maxSessionsPreventsLogin(true);
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
	static class ConcurrencyControlInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.formLogin(withDefaults())
				.sessionManagement((sessionManagement) ->
					sessionManagement
						.sessionConcurrency((sessionConcurrency) ->
							sessionConcurrency
								.maximumSessions(1)
								.maxSessionsPreventsLogin(true)
						)
				);
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
	static class SessionCreationPolicyStateLessInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement((sessionManagement) ->
					sessionManagement
						.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				);
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
				.sessionManagement()
					.maximumSessions(1);
			return http.build();
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

	@Configuration
	@EnableWebSecurity
	static class SharedTrustResolverConfig {

		static AuthenticationTrustResolver TR;

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement((sessions) -> sessions
					.requireExplicitAuthenticationStrategy(false)
				)
				.setSharedObject(AuthenticationTrustResolver.class, TR);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class SessionRegistryOneBeanConfig {

		private static SessionRegistry SESSION_REGISTRY;

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement()
				.maximumSessions(1);
			return http.build();
			// @formatter:on
		}

		@Bean
		SessionRegistry sessionRegistry() {
			return SESSION_REGISTRY;
		}

	}

	@Configuration
	@EnableWebSecurity
	static class SessionRegistryTwoBeansConfig {

		private static SessionRegistry SESSION_REGISTRY_ONE;

		private static SessionRegistry SESSION_REGISTRY_TWO;

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement()
				.maximumSessions(1);
			return http.build();
			// @formatter:on
		}

		@Bean
		SessionRegistry sessionRegistryOne() {
			return SESSION_REGISTRY_ONE;
		}

		@Bean
		SessionRegistry sessionRegistryTwo() {
			return SESSION_REGISTRY_TWO;
		}

	}

	@Configuration
	@EnableWebSecurity
	static class DefaultUrlRewriteConfig {

		@Bean
		DefaultSecurityFilterChain configure(HttpSecurity http) throws Exception {
			return http.build();
		}

		@Bean
		EncodesUrls encodesUrls() {
			return new EncodesUrls();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class EnableUrlRewriteConfig {

		@Bean
		DefaultSecurityFilterChain configure(HttpSecurity http) throws Exception {
			http.sessionManagement((sessions) -> sessions.enableSessionUrlRewriting(true));
			return http.build();
		}

		@Bean
		EncodesUrls encodesUrls() {
			return new EncodesUrls();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class HttpBasicSessionCreationPolicyStatelessConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.sessionManagement((sessionManagement) ->
					sessionManagement
						.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				)
				.httpBasic(withDefaults());
			// @formatter:on
			return http.build();
		}

		@Bean
		UserDetailsService userDetailsService() {
			return new InMemoryUserDetailsManager(PasswordEncodedUser.user());
		}

		@Bean
		EncodesUrls encodesUrls() {
			return new EncodesUrls();
		}

	}

	@RestController
	static class EncodesUrls {

		@RequestMapping("/")
		String encoded(HttpServletResponse response) {
			response.encodeURL("/foo");
			response.encodeRedirectURL("/foo");
			return "encoded";
		}

	}

}
