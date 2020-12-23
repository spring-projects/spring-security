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
import java.security.Principal;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.apache.http.HttpStatus;
import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.util.FieldUtils;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessEventPublishingLogoutHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests session-related functionality for the &lt;http&gt; namespace element and
 * &lt;session-management&gt;
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @author Josh Cummings
 * @author Onur Kagan Ozcan
 * @author Mazen Aissa
 */
public class SessionManagementConfigTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/SessionManagementConfigTests";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void requestWhenCreateSessionAlwaysThenAlwaysCreatesSession() throws Exception {
		this.spring.configLocations(xml("CreateSessionAlways")).autowire();
		MockHttpServletRequest request = get("/").buildRequest(this.servletContext());
		MockHttpServletResponse response = request(request, this.spring.getContext());
		assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
		assertThat(request.getSession(false)).isNotNull();
	}

	@Test
	public void requestWhenCreateSessionIsSetToNeverThenDoesNotCreateSessionOnLoginChallenge() throws Exception {
		this.spring.configLocations(xml("CreateSessionNever")).autowire();
		MockHttpServletRequest request = get("/auth").buildRequest(this.servletContext());
		MockHttpServletResponse response = request(request, this.spring.getContext());
		assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_MOVED_TEMPORARILY);
		assertThat(request.getSession(false)).isNull();
	}

	@Test
	public void requestWhenCreateSessionIsSetToNeverThenDoesNotCreateSessionOnLogin() throws Exception {
		this.spring.configLocations(xml("CreateSessionNever")).autowire();
		// @formatter:off
		MockHttpServletRequest request = post("/login")
				.param("username", "user")
				.param("password", "password")
				.buildRequest(this.servletContext());
		// @formatter:on
		request = csrf().postProcessRequest(request);
		MockHttpServletResponse response = request(request, this.spring.getContext());
		assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_MOVED_TEMPORARILY);
		assertThat(request.getSession(false)).isNull();
	}

	@Test
	public void requestWhenCreateSessionIsSetToNeverThenUsesExistingSession() throws Exception {
		this.spring.configLocations(xml("CreateSessionNever")).autowire();
		// @formatter:off
		MockHttpServletRequest request = post("/login")
				.param("username", "user")
				.param("password", "password")
				.buildRequest(this.servletContext());
		// @formatter:on
		request = csrf().postProcessRequest(request);
		MockHttpSession session = new MockHttpSession();
		request.setSession(session);
		MockHttpServletResponse response = request(request, this.spring.getContext());
		assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_MOVED_TEMPORARILY);
		assertThat(request.getSession(false)).isNotNull();
		assertThat(request.getSession(false)
				.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).isNotNull();
	}

	@Test
	public void requestWhenCreateSessionIsSetToStatelessThenDoesNotCreateSessionOnLoginChallenge() throws Exception {
		this.spring.configLocations(xml("CreateSessionStateless")).autowire();
		// @formatter:off
		this.mvc.perform(get("/auth"))
				.andExpect(status().isFound())
				.andExpect(session().exists(false));
		// @formatter:on
	}

	@Test
	public void requestWhenCreateSessionIsSetToStatelessThenDoesNotCreateSessionOnLogin() throws Exception {
		this.spring.configLocations(xml("CreateSessionStateless")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.param("username", "user")
				.param("password", "password")
				.with(csrf());
		this.mvc.perform(loginRequest)
				.andExpect(status().isFound())
				.andExpect(session().exists(false));
		// @formatter:on
	}

	@Test
	public void requestWhenCreateSessionIsSetToStatelessThenIgnoresExistingSession() throws Exception {
		this.spring.configLocations(xml("CreateSessionStateless")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder loginRequest = post("/login")
				.param("username", "user")
				.param("password", "password")
				.session(new MockHttpSession())
				.with(csrf());
		MvcResult result = this.mvc.perform(loginRequest)
				.andExpect(status().isFound())
				.andExpect(session()).andReturn();
		// @formatter:on
		assertThat(result.getRequest().getSession(false)
				.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).isNull();
	}

	@Test
	public void requestWhenCreateSessionIsSetToIfRequiredThenDoesNotCreateSessionOnPublicInvocation() throws Exception {
		this.spring.configLocations(xml("CreateSessionIfRequired")).autowire();
		ServletContext servletContext = this.mvc.getDispatcherServlet().getServletContext();
		MockHttpServletRequest request = get("/").buildRequest(servletContext);
		MockHttpServletResponse response = request(request, this.spring.getContext());
		assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
		assertThat(request.getSession(false)).isNull();
	}

	@Test
	public void requestWhenCreateSessionIsSetToIfRequiredThenCreatesSessionOnLoginChallenge() throws Exception {
		this.spring.configLocations(xml("CreateSessionIfRequired")).autowire();
		ServletContext servletContext = this.mvc.getDispatcherServlet().getServletContext();
		MockHttpServletRequest request = get("/auth").buildRequest(servletContext);
		MockHttpServletResponse response = request(request, this.spring.getContext());
		assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_MOVED_TEMPORARILY);
		assertThat(request.getSession(false)).isNotNull();
	}

	@Test
	public void requestWhenCreateSessionIsSetToIfRequiredThenCreatesSessionOnLogin() throws Exception {
		this.spring.configLocations(xml("CreateSessionIfRequired")).autowire();
		ServletContext servletContext = this.mvc.getDispatcherServlet().getServletContext();
		// @formatter:off
		MockHttpServletRequest request = post("/login")
				.param("username", "user")
				.param("password", "password")
				.buildRequest(servletContext);
		// @formatter:on
		request = csrf().postProcessRequest(request);
		MockHttpServletResponse response = request(request, this.spring.getContext());
		assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_MOVED_TEMPORARILY);
		assertThat(request.getSession(false)).isNotNull();
	}

	/**
	 * SEC-1208
	 */
	@Test
	public void requestWhenRejectingUserBasedOnMaxSessionsExceededThenDoesNotCreateSession() throws Exception {
		this.spring.configLocations(xml("Sec1208")).autowire();
		// @formatter:off
		this.mvc.perform(get("/auth").with(httpBasic("user", "password")))
				.andExpect(status().isOk())
				.andExpect(session());
		this.mvc.perform(get("/auth").with(httpBasic("user", "password")))
				.andExpect(status().isUnauthorized())
				.andExpect(session().exists(false));
		// @formatter:on
	}

	/**
	 * SEC-2137
	 */
	@Test
	public void requestWhenSessionFixationProtectionDisabledAndConcurrencyControlEnabledThenSessionNotInvalidated()
			throws Exception {
		this.spring.configLocations(xml("Sec2137")).autowire();
		MockHttpSession session = new MockHttpSession();
		// @formatter:off
		this.mvc.perform(get("/auth").session(session).with(httpBasic("user", "password")))
				.andExpect(status().isOk())
				.andExpect(session().id(session.getId()));
		// @formatter:on
	}

	@Test
	public void autowireWhenExportingSessionRegistryBeanThenAvailableForWiring() {
		this.spring.configLocations(xml("ConcurrencyControlSessionRegistryAlias")).autowire();
		this.sessionRegistryIsValid();
	}

	@Test
	public void requestWhenExpiredUrlIsSetThenInvalidatesSessionAndRedirects() throws Exception {
		this.spring.configLocations(xml("ConcurrencyControlExpiredUrl")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder request = get("/auth")
				.session(expiredSession())
				.with(httpBasic("user", "password"));
		this.mvc.perform(request)
				.andExpect(redirectedUrl("/expired"))
				.andExpect(session().exists(false));
		// @formatter:on
	}

	@Test
	public void requestWhenConcurrencyControlAndCustomLogoutHandlersAreSetThenAllAreInvokedWhenSessionExpires()
			throws Exception {
		this.spring.configLocations(xml("ConcurrencyControlLogoutAndRememberMeHandlers")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder request = get("/auth")
				.session(expiredSession())
				.with(httpBasic("user", "password"));
		this.mvc.perform(request)
				.andExpect(status().isOk())
				.andExpect(cookie().maxAge("testCookie", 0))
				.andExpect(cookie().exists("rememberMeCookie"))
				.andExpect(session().valid(true));
		// @formatter:on
	}

	@Test
	public void requestWhenConcurrencyControlAndRememberMeAreSetThenInvokedWhenSessionExpires() throws Exception {
		this.spring.configLocations(xml("ConcurrencyControlRememberMeHandler")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder request = get("/auth")
				.session(expiredSession())
				.with(httpBasic("user", "password"));
		this.mvc.perform(request)
				.andExpect(status().isOk()).andExpect(cookie().exists("rememberMeCookie"))
				.andExpect(session().exists(false));
		// @formatter:on
	}

	/**
	 * SEC-2057
	 */
	@Test
	public void autowireWhenConcurrencyControlIsSetThenLogoutHandlersGetAuthenticationObject() throws Exception {
		this.spring.configLocations(xml("ConcurrencyControlCustomLogoutHandler")).autowire();
		MvcResult result = this.mvc.perform(get("/auth").with(httpBasic("user", "password"))).andExpect(session())
				.andReturn();
		MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
		SessionRegistry sessionRegistry = this.spring.getContext().getBean(SessionRegistry.class);
		sessionRegistry.getSessionInformation(session.getId()).expireNow();
		// @formatter:off
		this.mvc.perform(get("/auth").session(session))
				.andExpect(header().string("X-Username", "user"));
		// @formatter:on
	}

	@Test
	public void requestWhenConcurrencyControlIsSetThenDefaultsToResponseBodyExpirationResponse() throws Exception {
		this.spring.configLocations(xml("ConcurrencyControlSessionRegistryAlias")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder request = get("/auth")
				.session(expiredSession())
				.with(httpBasic("user", "password"));
		this.mvc.perform(request)
				.andExpect(content().string("This session has been expired (possibly due to multiple concurrent "
						+ "logins being attempted as the same user)."));
		// @formatter:on
	}

	@Test
	public void requestWhenCustomSessionAuthenticationStrategyThenInvokesOnAuthentication() throws Exception {
		this.spring.configLocations(xml("SessionAuthenticationStrategyRef")).autowire();
		// @formatter:off
		this.mvc.perform(get("/auth").with(httpBasic("user", "password")))
				.andExpect(status().isIAmATeapot());
		// @formatter:on
	}

	@Test
	public void autowireWhenSessionRegistryRefIsSetThenAvailableForWiring() {
		this.spring.configLocations(xml("ConcurrencyControlSessionRegistryRef")).autowire();
		this.sessionRegistryIsValid();
	}

	@Test
	public void requestWhenMaxSessionsIsSetThenErrorsWhenExceeded() throws Exception {
		this.spring.configLocations(xml("ConcurrencyControlMaxSessions")).autowire();
		// @formatter:off
		this.mvc.perform(get("/auth").with(httpBasic("user", "password")))
				.andExpect(status().isOk());
		this.mvc.perform(get("/auth").with(httpBasic("user", "password")))
				.andExpect(status().isOk());
		this.mvc.perform(get("/auth").with(httpBasic("user", "password")))
				.andExpect(redirectedUrl("/max-exceeded"));
		// @formatter:on
	}

	@Test
	public void requestWhenMaxSessionsIsSetWithPlaceHolderThenErrorsWhenExceeded() throws Exception {
		System.setProperty("sessionManagement.maxSessions", "1");
		this.spring.configLocations(xml("ConcurrencyControlMaxSessionsPlaceHolder")).autowire();
		// @formatter:off
		this.mvc.perform(get("/auth").with(httpBasic("user", "password")))
				.andExpect(status().isOk());
		this.mvc.perform(get("/auth").with(httpBasic("user", "password")))
				.andExpect(redirectedUrl("/max-exceeded"));
		// @formatter:on
	}
	
	@Test
	public void autowireWhenSessionFixationProtectionIsNoneAndCsrfDisabledThenSessionManagementFilterIsNotWired() {
		this.spring.configLocations(xml("NoSessionManagementFilter")).autowire();
		assertThat(this.getFilter(SessionManagementFilter.class)).isNull();
	}

	@Test
	public void requestWhenSessionFixationProtectionIsNoneThenSessionNotInvalidated() throws Exception {
		this.spring.configLocations(xml("SessionFixationProtectionNone")).autowire();
		MockHttpSession session = new MockHttpSession();
		String sessionId = session.getId();
		// @formatter:off
		this.mvc.perform(get("/auth").session(session).with(httpBasic("user", "password")))
				.andExpect(session().id(sessionId));
		// @formatter:on
	}

	@Test
	public void requestWhenSessionFixationProtectionIsMigrateSessionThenSessionIsReplaced() throws Exception {
		this.spring.configLocations(xml("SessionFixationProtectionMigrateSession")).autowire();
		MockHttpSession session = new MockHttpSession();
		String sessionId = session.getId();
		// @formatter:off
		MvcResult result = this.mvc.perform(get("/auth").session(session).with(httpBasic("user", "password")))
				.andExpect(session())
				.andReturn();
		// @formatter:on
		assertThat(result.getRequest().getSession(false).getId()).isNotEqualTo(sessionId);
	}

	@Test
	public void requestWhenSessionFixationProtectionIsNoneAndInvalidSessionUrlIsSetThenStillRedirectsOnInvalidSession()
			throws Exception {
		this.spring.configLocations(xml("SessionFixationProtectionNoneWithInvalidSessionUrl")).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder authRequest = get("/auth")
				.with((request) -> {
					request.setRequestedSessionId("1");
					request.setRequestedSessionIdValid(false);
					return request;
				});
		this.mvc.perform(authRequest)
				.andExpect(redirectedUrl("/timeoutUrl"));
		// @formatter:on
	}

	private void sessionRegistryIsValid() {
		SessionRegistry sessionRegistry = this.spring.getContext().getBean("sessionRegistry", SessionRegistry.class);
		assertThat(sessionRegistry).isNotNull();
		assertThat(this.getFilter(ConcurrentSessionFilter.class)).returns(sessionRegistry,
				this::extractSessionRegistry);
		assertThat(this.getFilter(UsernamePasswordAuthenticationFilter.class)).returns(sessionRegistry,
				this::extractSessionRegistry);
		// SEC-1143
		assertThat(this.getFilter(SessionManagementFilter.class)).returns(sessionRegistry,
				this::extractSessionRegistry);
	}

	private SessionRegistry extractSessionRegistry(ConcurrentSessionFilter filter) {
		return getFieldValue(filter, "sessionRegistry");
	}

	private SessionRegistry extractSessionRegistry(UsernamePasswordAuthenticationFilter filter) {
		SessionAuthenticationStrategy strategy = getFieldValue(filter, "sessionStrategy");
		List<SessionAuthenticationStrategy> strategies = getFieldValue(strategy, "delegateStrategies");
		return getFieldValue(strategies.get(0), "sessionRegistry");
	}

	private SessionRegistry extractSessionRegistry(SessionManagementFilter filter) {
		SessionAuthenticationStrategy strategy = getFieldValue(filter, "sessionAuthenticationStrategy");
		List<SessionAuthenticationStrategy> strategies = getFieldValue(strategy, "delegateStrategies");
		return getFieldValue(strategies.get(0), "sessionRegistry");
	}

	private <T> T getFieldValue(Object target, String fieldName) {
		try {
			return (T) FieldUtils.getFieldValue(target, fieldName);
		}
		catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}

	private static SessionResultMatcher session() {
		return new SessionResultMatcher();
	}

	/**
	 * SEC-2680
	 */
	@Test
	public void checkConcurrencyAndLogoutFilterHasSameSizeAndHasLogoutSuccessEventPublishingLogoutHandler() {
		this.spring.configLocations(xml("ConcurrencyControlLogoutAndRememberMeHandlers")).autowire();
		ConcurrentSessionFilter concurrentSessionFilter = getFilter(ConcurrentSessionFilter.class);
		LogoutFilter logoutFilter = getFilter(LogoutFilter.class);
		LogoutHandler csfLogoutHandler = getFieldValue(concurrentSessionFilter, "handlers");
		LogoutHandler lfLogoutHandler = getFieldValue(logoutFilter, "handler");
		assertThat(csfLogoutHandler).isInstanceOf(CompositeLogoutHandler.class);
		assertThat(lfLogoutHandler).isInstanceOf(CompositeLogoutHandler.class);
		List<LogoutHandler> csfLogoutHandlers = getFieldValue(csfLogoutHandler, "logoutHandlers");
		List<LogoutHandler> lfLogoutHandlers = getFieldValue(lfLogoutHandler, "logoutHandlers");
		assertThat(csfLogoutHandlers).hasSameSizeAs(lfLogoutHandlers);
		assertThat(csfLogoutHandlers).hasAtLeastOneElementOfType(LogoutSuccessEventPublishingLogoutHandler.class);
		assertThat(lfLogoutHandlers).hasAtLeastOneElementOfType(LogoutSuccessEventPublishingLogoutHandler.class);
	}

	private static MockHttpServletResponse request(MockHttpServletRequest request, ApplicationContext context)
			throws IOException, ServletException {
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChainProxy proxy = context.getBean(FilterChainProxy.class);
		proxy.doFilter(request, new EncodeUrlDenyingHttpServletResponseWrapper(response), (req, resp) -> {
		});
		return response;
	}

	private MockHttpSession expiredSession() {
		MockHttpSession session = new MockHttpSession();
		SessionRegistry sessionRegistry = this.spring.getContext().getBean(SessionRegistry.class);
		sessionRegistry.registerNewSession(session.getId(), "user");
		sessionRegistry.getSessionInformation(session.getId()).expireNow();
		return session;
	}

	private <T extends Filter> T getFilter(Class<T> filterClass) {
		return (T) getFilters().stream().filter(filterClass::isInstance).findFirst().orElse(null);
	}

	private List<Filter> getFilters() {
		FilterChainProxy proxy = this.spring.getContext().getBean(FilterChainProxy.class);
		return proxy.getFilters("/");
	}

	private ServletContext servletContext() {
		WebApplicationContext context = this.spring.getContext();
		return context.getServletContext();
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	static class TeapotSessionAuthenticationStrategy implements SessionAuthenticationStrategy {

		@Override
		public void onAuthentication(Authentication authentication, HttpServletRequest request,
				HttpServletResponse response) throws SessionAuthenticationException {
			response.setStatus(org.springframework.http.HttpStatus.I_AM_A_TEAPOT.value());
		}

	}

	static class CustomRememberMeServices implements RememberMeServices, LogoutHandler {

		@Override
		public Authentication autoLogin(HttpServletRequest request, HttpServletResponse response) {
			return null;
		}

		@Override
		public void loginFail(HttpServletRequest request, HttpServletResponse response) {
		}

		@Override
		public void loginSuccess(HttpServletRequest request, HttpServletResponse response,
				Authentication successfulAuthentication) {
		}

		@Override
		public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
			response.addHeader("X-Username", authentication.getName());
		}

	}

	@RestController
	static class BasicController {

		@GetMapping("/")
		String ok() {
			return "ok";
		}

		@GetMapping("/auth")
		String auth(Principal principal) {
			return principal.getName();
		}

	}

	private static class SessionResultMatcher implements ResultMatcher {

		private String id;

		private Boolean valid;

		private Boolean exists = true;

		ResultMatcher exists(boolean exists) {
			this.exists = exists;
			return this;
		}

		ResultMatcher valid(boolean valid) {
			this.valid = valid;
			return this.exists(true);
		}

		ResultMatcher id(String id) {
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

	private static class EncodeUrlDenyingHttpServletResponseWrapper extends HttpServletResponseWrapper {

		EncodeUrlDenyingHttpServletResponseWrapper(HttpServletResponse response) {
			super(response);
		}

		@Override
		public String encodeURL(String url) {
			throw new RuntimeException("Unexpected invocation of encodeURL");
		}

		@Override
		public String encodeRedirectURL(String url) {
			throw new RuntimeException("Unexpected invocation of encodeURL");
		}

		@Override
		public String encodeUrl(String url) {
			throw new RuntimeException("Unexpected invocation of encodeURL");
		}

		@Override
		public String encodeRedirectUrl(String url) {
			throw new RuntimeException("Unexpected invocation of encodeURL");
		}

	}

}