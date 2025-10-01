/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.authentication;

import java.util.ArrayList;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.commons.logging.Log;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServicesTests;
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.firewall.DefaultHttpFirewall;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.security.web.servlet.TestMockHttpServletRequests.Builder;
import static org.springframework.security.web.servlet.TestMockHttpServletRequests.get;
import static org.springframework.security.web.servlet.TestMockHttpServletRequests.post;
import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.pathPattern;

/**
 * Tests {@link AbstractAuthenticationProcessingFilter}.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @author Rob Winch
 */
@SuppressWarnings("deprecation")
public class AbstractAuthenticationProcessingFilterTests {

	SavedRequestAwareAuthenticationSuccessHandler successHandler;

	SimpleUrlAuthenticationFailureHandler failureHandler;

	private MockHttpServletRequest createMockAuthenticationRequest() {
		return withMockAuthenticationRequest().build();
	}

	private Builder withMockAuthenticationRequest() {
		return get("www.example.com").requestUri("/mycontext", "/j_mock_post", null);
	}

	@BeforeEach
	public void setUp() {
		this.successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
		this.successHandler.setDefaultTargetUrl("/logged_in.jsp");
		this.failureHandler = new SimpleUrlAuthenticationFailureHandler();
		this.failureHandler.setDefaultFailureUrl("/failed.jsp");
		SecurityContextHolder.clearContext();
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testDefaultProcessesFilterUrlMatchesWithPathParameter() {
		MockHttpServletRequest request = post("/login;jsessionid=I8MIONOSTHOR").build();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockAuthenticationFilter filter = new MockAuthenticationFilter();
		filter.setFilterProcessesUrl("/login");
		DefaultHttpFirewall firewall = new DefaultHttpFirewall();
		// the firewall ensures that path parameters are ignored
		HttpServletRequest firewallRequest = firewall.getFirewalledRequest(request);
		assertThat(filter.requiresAuthentication(firewallRequest, response)).isTrue();
	}

	@Test
	public void testFilterProcessesUrlVariationsRespected() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = withMockAuthenticationRequest()
			.requestUri("/mycontext", "/j_OTHER_LOCATION", null)
			.build();
		// Setup our filter configuration
		MockFilterConfig config = new MockFilterConfig(null, null);
		// Setup our expectation that the filter chain will not be invoked, as we redirect
		// to defaultTargetUrl
		MockFilterChain chain = new MockFilterChain(false);
		MockHttpServletResponse response = new MockHttpServletResponse();
		// Setup our test object, to grant access
		MockAuthenticationFilter filter = new MockAuthenticationFilter(true);
		filter.setFilterProcessesUrl("/j_OTHER_LOCATION");
		filter.setAuthenticationSuccessHandler(this.successHandler);
		// Test
		filter.doFilter(request, response, chain);
		assertThat(response.getRedirectedUrl()).isEqualTo("/mycontext/logged_in.jsp");
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString()).isEqualTo("test");
	}

	@Test
	public void testGettersSetters() {
		AbstractAuthenticationProcessingFilter filter = new MockAuthenticationFilter();
		filter.setAuthenticationManager(mock(AuthenticationManager.class));
		filter.setFilterProcessesUrl("/p");
		filter.afterPropertiesSet();
		assertThat(filter.getRememberMeServices()).isNotNull();
		filter.setRememberMeServices(
				new TokenBasedRememberMeServices("key", new AbstractRememberMeServicesTests.MockUserDetailsService()));
		assertThat(filter.getRememberMeServices().getClass()).isEqualTo(TokenBasedRememberMeServices.class);
		assertThat(filter.getAuthenticationManager() != null).isTrue();
	}

	@Test
	public void testIgnoresAnyServletPathOtherThanFilterProcessesUrl() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = withMockAuthenticationRequest()
			.requestUri("/mycontext", "/some.file.html", null)
			.build();
		// Setup our filter configuration
		MockFilterConfig config = new MockFilterConfig(null, null);
		// Setup our expectation that the filter chain will be invoked, as our request is
		// for a page the filter isn't monitoring
		MockFilterChain chain = new MockFilterChain(true);
		MockHttpServletResponse response = new MockHttpServletResponse();
		// Setup our test object, to deny access
		MockAuthenticationFilter filter = new MockAuthenticationFilter(false);
		// Test
		filter.doFilter(request, response, chain);
	}

	@Test
	public void testNormalOperationWithDefaultFilterProcessesUrl() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = createMockAuthenticationRequest();
		HttpSession sessionPreAuth = request.getSession();
		// Setup our filter configuration
		MockFilterConfig config = new MockFilterConfig(null, null);
		// Setup our expectation that the filter chain will not be invoked, as we redirect
		// to defaultTargetUrl
		MockFilterChain chain = new MockFilterChain(false);
		MockHttpServletResponse response = new MockHttpServletResponse();
		// Setup our test object, to grant access
		MockAuthenticationFilter filter = new MockAuthenticationFilter(true);
		filter.setFilterProcessesUrl("/j_mock_post");
		filter.setSessionAuthenticationStrategy(mock(SessionAuthenticationStrategy.class));
		filter.setAuthenticationSuccessHandler(this.successHandler);
		filter.setAuthenticationFailureHandler(this.failureHandler);
		filter.setAuthenticationManager(mock(AuthenticationManager.class));
		filter.afterPropertiesSet();
		// Test
		filter.doFilter(request, response, chain);
		assertThat(response.getRedirectedUrl()).isEqualTo("/mycontext/logged_in.jsp");
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString()).isEqualTo("test");
		assertThat(request.getAttribute(RequestAttributeSecurityContextRepository.DEFAULT_REQUEST_ATTR_NAME))
			.isNotNull();
		// Should still have the same session
		assertThat(request.getSession()).isEqualTo(sessionPreAuth);
	}

	@Test
	public void testNormalOperationWithDefaultFilterProcessesUrlAndAuthenticationManager() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = createMockAuthenticationRequest();
		HttpSession sessionPreAuth = request.getSession();
		// Setup our filter configuration
		MockFilterConfig config = new MockFilterConfig(null, null);
		// Setup our expectation that the filter chain will not be invoked, as we redirect
		// to defaultTargetUrl
		MockFilterChain chain = new MockFilterChain(false);
		MockHttpServletResponse response = new MockHttpServletResponse();
		// Setup our test object, to grant access
		MockAuthenticationFilter filter = new MockAuthenticationFilter("/j_mock_post",
				mock(AuthenticationManager.class));
		filter.setSessionAuthenticationStrategy(mock(SessionAuthenticationStrategy.class));
		filter.setAuthenticationSuccessHandler(this.successHandler);
		filter.setAuthenticationFailureHandler(this.failureHandler);
		filter.afterPropertiesSet();
		// Test
		filter.doFilter(request, response, chain);
		assertThat(response.getRedirectedUrl()).isEqualTo("/mycontext/logged_in.jsp");
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString()).isEqualTo("test");
		assertThat(request.getAttribute(RequestAttributeSecurityContextRepository.DEFAULT_REQUEST_ATTR_NAME))
			.isNotNull();
		// Should still have the same session
		assertThat(request.getSession()).isEqualTo(sessionPreAuth);
	}

	@Test
	public void testNormalOperationWithRequestMatcherAndAuthenticationManager() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = withMockAuthenticationRequest()
			.requestUri("/mycontext", "/j_eradicate_corona_virus", null)
			.build();
		HttpSession sessionPreAuth = request.getSession();
		// Setup our filter configuration
		MockFilterConfig config = new MockFilterConfig(null, null);
		// Setup our expectation that the filter chain will not be invoked, as we redirect
		// to defaultTargetUrl
		MockFilterChain chain = new MockFilterChain(false);
		MockHttpServletResponse response = new MockHttpServletResponse();
		// Setup our test object, to grant access
		MockAuthenticationFilter filter = new MockAuthenticationFilter(pathPattern("/j_eradicate_corona_virus"),
				mock(AuthenticationManager.class));
		filter.setSessionAuthenticationStrategy(mock(SessionAuthenticationStrategy.class));
		filter.setAuthenticationSuccessHandler(this.successHandler);
		filter.setAuthenticationFailureHandler(this.failureHandler);
		filter.afterPropertiesSet();
		// Test
		filter.doFilter(request, response, chain);
		assertThat(response.getRedirectedUrl()).isEqualTo("/mycontext/logged_in.jsp");
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString()).isEqualTo("test");
		assertThat(request.getAttribute(RequestAttributeSecurityContextRepository.DEFAULT_REQUEST_ATTR_NAME))
			.isNotNull();
		// Should still have the same session
		assertThat(request.getSession()).isEqualTo(sessionPreAuth);
	}

	@Test
	public void testStartupDetectsInvalidAuthenticationManager() {
		AbstractAuthenticationProcessingFilter filter = new MockAuthenticationFilter();
		filter.setAuthenticationFailureHandler(this.failureHandler);
		this.successHandler.setDefaultTargetUrl("/");
		filter.setAuthenticationSuccessHandler(this.successHandler);
		filter.setFilterProcessesUrl("/login");
		assertThatIllegalArgumentException().isThrownBy(filter::afterPropertiesSet)
			.withMessage("authenticationManager must be specified");
	}

	@Test
	public void testStartupDetectsInvalidFilterProcessesUrl() {
		AbstractAuthenticationProcessingFilter filter = new MockAuthenticationFilter();
		filter.setAuthenticationFailureHandler(this.failureHandler);
		filter.setAuthenticationManager(mock(AuthenticationManager.class));
		filter.setAuthenticationSuccessHandler(this.successHandler);
		assertThatIllegalArgumentException().isThrownBy(() -> filter.setFilterProcessesUrl(null))
			.withMessage("pattern cannot be null");
	}

	@Test
	public void testSuccessLoginThenFailureLoginResultsInSessionLosingToken() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = createMockAuthenticationRequest();
		// Setup our filter configuration
		MockFilterConfig config = new MockFilterConfig(null, null);
		// Setup our expectation that the filter chain will not be invoked, as we redirect
		// to defaultTargetUrl
		MockFilterChain chain = new MockFilterChain(false);
		MockHttpServletResponse response = new MockHttpServletResponse();
		// Setup our test object, to grant access
		MockAuthenticationFilter filter = new MockAuthenticationFilter(true);
		filter.setFilterProcessesUrl("/j_mock_post");
		filter.setAuthenticationSuccessHandler(this.successHandler);
		// Test
		filter.doFilter(request, response, chain);
		assertThat(response.getRedirectedUrl()).isEqualTo("/mycontext/logged_in.jsp");
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString()).isEqualTo("test");
		// Now try again but this time have filter deny access
		// Setup our HTTP request
		// Setup our expectation that the filter chain will not be invoked, as we redirect
		// to authenticationFailureUrl
		chain = new MockFilterChain(false);
		response = new MockHttpServletResponse();
		// Setup our test object, to deny access
		filter = new MockAuthenticationFilter(false);
		filter.setFilterProcessesUrl("/j_mock_post");
		filter.setAuthenticationFailureHandler(this.failureHandler);
		// Test
		filter.doFilter(request, response, chain);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void testSuccessfulAuthenticationInvokesSuccessHandlerAndSetsContext() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = createMockAuthenticationRequest();
		// Setup our filter configuration
		MockFilterConfig config = new MockFilterConfig(null, null);
		// Setup our expectation that the filter chain will be invoked, as we want to go
		// to the location requested in the session
		MockFilterChain chain = new MockFilterChain(true);
		MockHttpServletResponse response = new MockHttpServletResponse();
		// Setup our test object, to grant access
		MockAuthenticationFilter filter = new MockAuthenticationFilter(true);
		filter.setFilterProcessesUrl("/j_mock_post");
		AuthenticationSuccessHandler successHandler = mock(AuthenticationSuccessHandler.class);
		filter.setAuthenticationSuccessHandler(successHandler);
		// Test
		filter.doFilter(request, response, chain);
		verify(successHandler).onAuthenticationSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
				any(Authentication.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(request.getAttribute(RequestAttributeSecurityContextRepository.DEFAULT_REQUEST_ATTR_NAME))
			.isNotNull();
	}

	@Test
	public void testSuccessfulAuthenticationThenDefaultDoesNotCreateSession() throws Exception {
		Authentication authentication = TestAuthentication.authenticatedUser();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain(false);
		MockAuthenticationFilter filter = new MockAuthenticationFilter();

		filter.successfulAuthentication(request, response, chain, authentication);

		assertThat(request.getSession(false)).isNull();
	}

	@Test
	public void testSuccessfulAuthenticationWhenCustomSecurityContextRepositoryThenAuthenticationSaved()
			throws Exception {
		ArgumentCaptor<SecurityContext> contextCaptor = ArgumentCaptor.forClass(SecurityContext.class);
		SecurityContextRepository repository = mock(SecurityContextRepository.class);
		Authentication authentication = TestAuthentication.authenticatedUser();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockFilterChain chain = new MockFilterChain(false);
		MockAuthenticationFilter filter = new MockAuthenticationFilter();
		filter.setSecurityContextRepository(repository);

		filter.successfulAuthentication(request, response, chain, authentication);

		verify(repository).saveContext(contextCaptor.capture(), eq(request), eq(response));
		assertThat(contextCaptor.getValue().getAuthentication()).isEqualTo(authentication);
	}

	@Test
	public void testFailedAuthenticationInvokesFailureHandler() throws Exception {
		// Setup our HTTP request
		MockHttpServletRequest request = createMockAuthenticationRequest();
		// Setup our filter configuration
		MockFilterConfig config = new MockFilterConfig(null, null);
		// Setup our expectation that the filter chain will not be invoked, as we redirect
		// to authenticationFailureUrl
		MockFilterChain chain = new MockFilterChain(false);
		MockHttpServletResponse response = new MockHttpServletResponse();
		// Setup our test object, to deny access
		MockAuthenticationFilter filter = new MockAuthenticationFilter(false);
		AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
		filter.setAuthenticationFailureHandler(failureHandler);
		// Test
		filter.doFilter(request, response, chain);
		verify(failureHandler).onAuthenticationFailure(any(HttpServletRequest.class), any(HttpServletResponse.class),
				any(AuthenticationException.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	/**
	 * SEC-571
	 */
	@Test
	public void testNoSessionIsCreatedIfAllowSessionCreationIsFalse() throws Exception {
		MockHttpServletRequest request = createMockAuthenticationRequest();
		MockFilterConfig config = new MockFilterConfig(null, null);
		MockFilterChain chain = new MockFilterChain(true);
		MockHttpServletResponse response = new MockHttpServletResponse();
		// Reject authentication, so exception would normally be stored in session
		MockAuthenticationFilter filter = new MockAuthenticationFilter(false);
		this.failureHandler.setAllowSessionCreation(false);
		filter.setAuthenticationFailureHandler(this.failureHandler);
		filter.doFilter(request, response, chain);
		assertThat(request.getSession(false)).isNull();
	}

	/**
	 * SEC-462
	 */
	@Test
	public void testLoginErrorWithNoFailureUrlSendsUnauthorizedStatus() throws Exception {
		MockHttpServletRequest request = createMockAuthenticationRequest();
		MockFilterConfig config = new MockFilterConfig(null, null);
		MockFilterChain chain = new MockFilterChain(true);
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockAuthenticationFilter filter = new MockAuthenticationFilter(false);
		this.successHandler.setDefaultTargetUrl("https://monkeymachine.co.uk/");
		filter.setAuthenticationSuccessHandler(this.successHandler);
		filter.doFilter(request, response, chain);
		assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
	}

	/**
	 * SEC-1919
	 */
	@Test
	public void loginErrorWithInternAuthenticationServiceExceptionLogsError() throws Exception {
		MockHttpServletRequest request = createMockAuthenticationRequest();
		MockFilterChain chain = new MockFilterChain(true);
		MockHttpServletResponse response = new MockHttpServletResponse();
		Log logger = mock(Log.class);
		MockAuthenticationFilter filter = new MockAuthenticationFilter(false);
		ReflectionTestUtils.setField(filter, "logger", logger);
		filter.exceptionToThrow = new InternalAuthenticationServiceException("Mock requested to do so");
		this.successHandler.setDefaultTargetUrl("https://monkeymachine.co.uk/");
		filter.setAuthenticationSuccessHandler(this.successHandler);
		filter.doFilter(request, response, chain);
		verify(logger).error(anyString(), eq(filter.exceptionToThrow));
		assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
	}

	@Test
	void doFilterWhenAuthenticatedThenCombinesAuthorities() throws Exception {
		String ROLE_EXISTING = "ROLE_EXISTING";
		TestingAuthenticationToken existingAuthn = new TestingAuthenticationToken("username", "password",
				ROLE_EXISTING);
		SecurityContextHolder.setContext(new SecurityContextImpl(existingAuthn));
		MockHttpServletRequest request = createMockAuthenticationRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockAuthenticationFilter filter = new MockAuthenticationFilter(true);
		filter.doFilter(request, response, new MockFilterChain(false));
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		assertThat(authentication.getAuthorities()).extracting(GrantedAuthority::getAuthority)
			.containsExactlyInAnyOrder(ROLE_EXISTING, "TEST");
	}

	/**
	 * This is critical to avoid adding duplicate GrantedAuthority instances with the
	 * same' authority when the issuedAt is too old and a new instance is requested.
	 * @throws Exception
	 */
	@Test
	void doFilterWhenDefaultEqualsAuthorityThenNoDuplicates() throws Exception {
		TestingAuthenticationToken existingAuthn = new TestingAuthenticationToken("username", "password",
				new DefaultEqualsGrantedAuthority());
		SecurityContextHolder.setContext(new SecurityContextImpl(existingAuthn));
		MockHttpServletRequest request = createMockAuthenticationRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockAuthenticationFilter filter = new MockAuthenticationFilter(
				new TestingAuthenticationToken("username", "password", new DefaultEqualsGrantedAuthority()));
		filter.doFilter(request, response, new MockFilterChain(false));
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		assertThat(new ArrayList<GrantedAuthority>(authentication.getAuthorities()))
			.extracting(GrantedAuthority::getAuthority)
			.containsExactly(DefaultEqualsGrantedAuthority.AUTHORITY);
	}

	/**
	 * https://github.com/spring-projects/spring-security/pull/3905
	 */
	@Test
	public void setRememberMeServicesShouldntAllowNulls() {
		AbstractAuthenticationProcessingFilter filter = new MockAuthenticationFilter();
		assertThatIllegalArgumentException().isThrownBy(() -> filter.setRememberMeServices(null));
	}

	private class MockAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

		private static final String DEFAULT_FILTER_PROCESSING_URL = "/j_mock_post";

		private AuthenticationException exceptionToThrow;

		private final @Nullable Authentication authentication;

		MockAuthenticationFilter(Authentication authentication) {
			super(DEFAULT_FILTER_PROCESSING_URL);
			this.authentication = authentication;
			setupRememberMeServicesAndAuthenticationException();
		}

		MockAuthenticationFilter(boolean grantAccess) {
			this(createDefaultAuthentication(grantAccess));
		}

		private MockAuthenticationFilter() {
			this(null);
		}

		private MockAuthenticationFilter(String defaultFilterProcessingUrl,
				AuthenticationManager authenticationManager) {
			super(defaultFilterProcessingUrl, authenticationManager);
			setupRememberMeServicesAndAuthenticationException();
			this.authentication = createDefaultAuthentication(true);
		}

		private MockAuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher,
				AuthenticationManager authenticationManager) {
			super(requiresAuthenticationRequestMatcher, authenticationManager);
			setupRememberMeServicesAndAuthenticationException();
			this.authentication = createDefaultAuthentication(true);
		}

		@Override
		public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
				throws AuthenticationException {
			if (this.authentication != null) {
				return this.authentication;
			}
			else {
				throw this.exceptionToThrow;
			}
		}

		private void setupRememberMeServicesAndAuthenticationException() {
			setRememberMeServices(new NullRememberMeServices());
			this.exceptionToThrow = new BadCredentialsException("Mock requested to do so");
		}

		private static @Nullable Authentication createDefaultAuthentication(boolean grantAccess) {
			if (!grantAccess) {
				return null;
			}
			return UsernamePasswordAuthenticationToken.authenticated("test", "test",
					AuthorityUtils.createAuthorityList("TEST"));
		}

	}

	private class MockFilterChain implements FilterChain {

		private boolean expectToProceed;

		MockFilterChain(boolean expectToProceed) {
			this.expectToProceed = expectToProceed;
		}

		@Override
		public void doFilter(ServletRequest request, ServletResponse response) {
			if (!this.expectToProceed) {
				fail("Did not expect filter chain to proceed");
			}
		}

	}

}
