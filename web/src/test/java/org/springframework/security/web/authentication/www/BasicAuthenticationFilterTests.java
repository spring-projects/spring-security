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

package org.springframework.security.web.authentication.www;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.NonBuildableAuthenticationToken;
import org.springframework.security.authentication.SecurityAssertions;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.test.web.CodecTestUtils;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.DefaultEqualsGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.WebUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.springframework.security.web.servlet.TestMockHttpServletRequests.get;
import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.pathPattern;

/**
 * Tests {@link BasicAuthenticationFilter}.
 *
 * @author Ben Alex
 * @author Andrey Litvitski
 */
public class BasicAuthenticationFilterTests {

	private BasicAuthenticationFilter filter;

	private AuthenticationManager manager;

	@BeforeEach
	public void setUp() {
		SecurityContextHolder.clearContext();
		UsernamePasswordAuthenticationToken rodRequest = UsernamePasswordAuthenticationToken.unauthenticated("rod",
				"koala");
		rodRequest.setDetails(new WebAuthenticationDetails(new MockHttpServletRequest()));
		Authentication rod = UsernamePasswordAuthenticationToken.authenticated("rod", "koala",
				AuthorityUtils.createAuthorityList("ROLE_1"));
		this.manager = mock(AuthenticationManager.class);
		given(this.manager.authenticate(rodRequest)).willReturn(rod);
		given(this.manager.authenticate(not(eq(rodRequest)))).willThrow(new BadCredentialsException(""));
		this.filter = new BasicAuthenticationFilter(this.manager, new BasicAuthenticationEntryPoint());
	}

	@AfterEach
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testFilterIgnoresRequestsContainingNoAuthorizationHeader() throws Exception {
		MockHttpServletRequest request = get("/some_file.html").build();
		final MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, response, chain);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		// Test
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void testGettersSetters() {
		assertThat(this.filter.getAuthenticationManager()).isNotNull();
		assertThat(this.filter.getAuthenticationEntryPoint()).isNotNull();
	}

	@Test
	public void testInvalidBasicAuthorizationTokenIsIgnored() throws Exception {
		String token = "NOT_A_VALID_TOKEN_AS_MISSING_COLON";
		MockHttpServletRequest request = get("/some_file.html").build();
		request.addHeader("Authorization", "Basic " + CodecTestUtils.encodeBase64(token));
		request.setSession(new MockHttpSession());
		final MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, response, chain);
		verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void invalidBase64IsIgnored() throws Exception {
		MockHttpServletRequest request = get("/some_file.html").build();
		request.addHeader("Authorization", "Basic NOT_VALID_BASE64");
		request.setSession(new MockHttpSession());
		final MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, response, chain);
		// The filter chain shouldn't proceed
		verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void testNormalOperation() throws Exception {
		String token = "rod:koala";
		MockHttpServletRequest request = get("/some_file.html").build();
		request.addHeader("Authorization", "Basic " + CodecTestUtils.encodeBase64(token));
		// Test
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, new MockHttpServletResponse(), chain);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("rod");
	}

	@Test
	public void testSecurityContextHolderStrategyUsed() throws Exception {
		String token = "rod:koala";
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Basic " + CodecTestUtils.encodeBase64(token.getBytes()));
		SecurityContextHolderStrategy strategy = spy(SecurityContextHolder.getContextHolderStrategy());
		this.filter.setSecurityContextHolderStrategy(strategy);
		this.filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
		ArgumentCaptor<SecurityContext> captor = ArgumentCaptor.forClass(SecurityContext.class);
		verify(strategy).setContext(captor.capture());
		assertThat(captor.getValue().getAuthentication()).isInstanceOf(UsernamePasswordAuthenticationToken.class);
	}

	// gh-5586
	@Test
	public void doFilterWhenSchemeLowercaseThenCaseInsensitveMatchWorks() throws Exception {
		String token = "rod:koala";
		MockHttpServletRequest request = get("/some_file.html").build();
		request.addHeader("Authorization", "basic " + CodecTestUtils.encodeBase64(token));
		// Test
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, new MockHttpServletResponse(), chain);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("rod");
	}

	@Test
	public void doFilterWhenSchemeMixedCaseThenCaseInsensitiveMatchWorks() throws Exception {
		String token = "rod:koala";
		MockHttpServletRequest request = get("/some_file.html").build();
		request.addHeader("Authorization", "BaSiC " + CodecTestUtils.encodeBase64(token));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, new MockHttpServletResponse(), chain);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("rod");
	}

	@Test
	public void testOtherAuthorizationSchemeIsIgnored() throws Exception {
		MockHttpServletRequest request = get("/some_file.html").build();
		request.addHeader("Authorization", "SOME_OTHER_AUTHENTICATION_SCHEME");
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, new MockHttpServletResponse(), chain);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void testStartupDetectsMissingAuthenticationEntryPoint() {
		assertThatIllegalArgumentException().isThrownBy(() -> new BasicAuthenticationFilter(this.manager, null));
	}

	@Test
	public void testStartupDetectsMissingAuthenticationManager() {
		assertThatIllegalArgumentException().isThrownBy(() -> new BasicAuthenticationFilter(null));
	}

	@Test
	public void testSuccessLoginThenFailureLoginResultsInSessionLosingToken() throws Exception {
		String token = "rod:koala";
		MockHttpServletRequest request = get("/some_file.html").build();
		request.addHeader("Authorization", "Basic " + CodecTestUtils.encodeBase64(token));
		final MockHttpServletResponse response1 = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, response1, chain);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		// Test
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("rod");
		// NOW PERFORM FAILED AUTHENTICATION
		token = "otherUser:WRONG_PASSWORD";
		request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Basic " + CodecTestUtils.encodeBase64(token));
		final MockHttpServletResponse response2 = new MockHttpServletResponse();
		chain = mock(FilterChain.class);
		this.filter.doFilter(request, response2, chain);
		verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		// Test - the filter chain will not be invoked, as we get a 401 forbidden response
		MockHttpServletResponse response = response2;
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void testWrongPasswordContinuesFilterChainIfIgnoreFailureIsTrue() throws Exception {
		String token = "rod:WRONG_PASSWORD";
		MockHttpServletRequest request = get("/some_file.html").build();
		request.addHeader("Authorization", "Basic " + CodecTestUtils.encodeBase64(token));
		request.setSession(new MockHttpSession());
		this.filter = new BasicAuthenticationFilter(this.manager);
		assertThat(this.filter.isIgnoreFailure()).isTrue();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, new MockHttpServletResponse(), chain);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		// Test - the filter chain will be invoked, as we've set ignoreFailure = true
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void testWrongPasswordReturnsForbiddenIfIgnoreFailureIsFalse() throws Exception {
		String token = "rod:WRONG_PASSWORD";
		MockHttpServletRequest request = get("/some_file.html").build();
		request.addHeader("Authorization", "Basic " + CodecTestUtils.encodeBase64(token));
		request.setSession(new MockHttpSession());
		assertThat(this.filter.isIgnoreFailure()).isFalse();
		final MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, response, chain);
		// Test - the filter chain will not be invoked, as we get a 401 forbidden response
		verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	// SEC-2054
	@Test
	public void skippedOnErrorDispatch() throws Exception {
		String token = "bad:credentials";
		MockHttpServletRequest request = get("/some_file.html").build();
		request.addHeader("Authorization", "Basic " + CodecTestUtils.encodeBase64(token));
		request.setAttribute(WebUtils.ERROR_REQUEST_URI_ATTRIBUTE, "/error");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, response, chain);
		assertThat(response.getStatus()).isEqualTo(200);
	}

	@Test
	public void doFilterWhenTokenAndFilterCharsetMatchDefaultThenAuthenticated() throws Exception {
		SecurityContextHolder.clearContext();
		UsernamePasswordAuthenticationToken rodRequest = UsernamePasswordAuthenticationToken.unauthenticated("rod",
				"äöü");
		rodRequest.setDetails(new WebAuthenticationDetails(new MockHttpServletRequest()));
		Authentication rod = UsernamePasswordAuthenticationToken.authenticated("rod", "äöü",
				AuthorityUtils.createAuthorityList("ROLE_1"));
		this.manager = mock(AuthenticationManager.class);
		given(this.manager.authenticate(rodRequest)).willReturn(rod);
		given(this.manager.authenticate(not(eq(rodRequest)))).willThrow(new BadCredentialsException(""));
		this.filter = new BasicAuthenticationFilter(this.manager, new BasicAuthenticationEntryPoint());
		String token = "rod:äöü";
		MockHttpServletRequest request = get("/some_file.html").build();
		request.addHeader("Authorization",
				"Basic " + CodecTestUtils.encodeBase64(token.getBytes(StandardCharsets.UTF_8)));
		MockHttpServletResponse response = new MockHttpServletResponse();
		// Test
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, response, chain);
		assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("rod");
		assertThat(SecurityContextHolder.getContext().getAuthentication().getCredentials()).isEqualTo("äöü");
	}

	@Test
	public void doFilterWhenTokenAndFilterCharsetMatchNonDefaultThenAuthenticated() throws Exception {
		SecurityContextHolder.clearContext();
		UsernamePasswordAuthenticationToken rodRequest = UsernamePasswordAuthenticationToken.unauthenticated("rod",
				"äöü");
		rodRequest.setDetails(new WebAuthenticationDetails(new MockHttpServletRequest()));
		Authentication rod = UsernamePasswordAuthenticationToken.authenticated("rod", "äöü",
				AuthorityUtils.createAuthorityList("ROLE_1"));
		this.manager = mock(AuthenticationManager.class);
		given(this.manager.authenticate(rodRequest)).willReturn(rod);
		given(this.manager.authenticate(not(eq(rodRequest)))).willThrow(new BadCredentialsException(""));
		this.filter = new BasicAuthenticationFilter(this.manager, new BasicAuthenticationEntryPoint());
		this.filter.setCredentialsCharset("ISO-8859-1");
		String token = "rod:äöü";
		MockHttpServletRequest request = get("/some_file.html").build();
		request.addHeader("Authorization",
				"Basic " + CodecTestUtils.encodeBase64(token.getBytes(StandardCharsets.ISO_8859_1)));
		MockHttpServletResponse response = new MockHttpServletResponse();
		// Test
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, response, chain);
		assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("rod");
		assertThat(SecurityContextHolder.getContext().getAuthentication().getCredentials()).isEqualTo("äöü");
		assertThat(request.getAttribute(RequestAttributeSecurityContextRepository.DEFAULT_REQUEST_ATTR_NAME))
			.isNotNull();
	}

	@Test
	public void doFilterWhenTokenAndFilterCharsetDoNotMatchThenUnauthorized() throws Exception {
		SecurityContextHolder.clearContext();
		UsernamePasswordAuthenticationToken rodRequest = UsernamePasswordAuthenticationToken.unauthenticated("rod",
				"äöü");
		rodRequest.setDetails(new WebAuthenticationDetails(new MockHttpServletRequest()));
		Authentication rod = UsernamePasswordAuthenticationToken.authenticated("rod", "äöü",
				AuthorityUtils.createAuthorityList("ROLE_1"));
		this.manager = mock(AuthenticationManager.class);
		given(this.manager.authenticate(rodRequest)).willReturn(rod);
		given(this.manager.authenticate(not(eq(rodRequest)))).willThrow(new BadCredentialsException(""));
		this.filter = new BasicAuthenticationFilter(this.manager, new BasicAuthenticationEntryPoint());
		this.filter.setCredentialsCharset("ISO-8859-1");
		String token = "rod:äöü";
		MockHttpServletRequest request = get("/some_file.html").build();
		request.addHeader("Authorization",
				"Basic " + CodecTestUtils.encodeBase64(token.getBytes(StandardCharsets.UTF_8)));
		MockHttpServletResponse response = new MockHttpServletResponse();
		// Test
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, response, chain);
		assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
		verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void requestWhenEmptyBasicAuthorizationHeaderTokenThenUnauthorized() throws Exception {
		MockHttpServletRequest request = get("/some_file.html").build();
		request.addHeader("Authorization", "Basic ");
		request.setSession(new MockHttpSession());
		final MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, response, chain);
		verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void requestWhenSecurityContextRepository() throws Exception {
		ArgumentCaptor<SecurityContext> contextArg = ArgumentCaptor.forClass(SecurityContext.class);
		SecurityContextRepository securityContextRepository = mock(SecurityContextRepository.class);
		this.filter.setSecurityContextRepository(securityContextRepository);
		String token = "rod:koala";
		MockHttpServletRequest request = get("/some_file.html").build();
		request.addHeader("Authorization", "Basic " + CodecTestUtils.encodeBase64(token));
		MockHttpServletResponse response = new MockHttpServletResponse();
		// Test
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, response, chain);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("rod");
		verify(securityContextRepository).saveContext(contextArg.capture(), eq(request), eq(response));
		assertThat(contextArg.getValue().getAuthentication().getName()).isEqualTo("rod");
	}

	@Test
	public void doFilterWhenUsernameDoesNotChangeThenAuthenticationIsNotRequired() throws Exception {
		SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
		SecurityContext securityContext = securityContextHolderStrategy.createEmptyContext();
		Authentication authentication = UsernamePasswordAuthenticationToken.authenticated("rod", "koala",
				AuthorityUtils.createAuthorityList("USER"));
		securityContext.setAuthentication(authentication);
		securityContextHolderStrategy.setContext(securityContext);

		String token = "rod:koala";
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Basic " + CodecTestUtils.encodeBase64(token));
		FilterChain filterChain = mock(FilterChain.class);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(200);

		verify(this.manager, never()).authenticate(any(Authentication.class));
		verify(filterChain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		verifyNoMoreInteractions(this.manager, filterChain);
	}

	@Test
	public void doFilterWhenUsernameChangesThenAuthenticationIsRequired() throws Exception {
		SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
		SecurityContext securityContext = securityContextHolderStrategy.createEmptyContext();
		Authentication authentication = UsernamePasswordAuthenticationToken.authenticated("user", "password",
				AuthorityUtils.createAuthorityList("USER"));
		securityContext.setAuthentication(authentication);
		securityContextHolderStrategy.setContext(securityContext);

		String token = "rod:koala";
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Basic " + CodecTestUtils.encodeBase64(token));
		FilterChain filterChain = mock(FilterChain.class);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(200);

		ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(this.manager).authenticate(authenticationCaptor.capture());
		verify(filterChain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		verifyNoMoreInteractions(this.manager, filterChain);

		Authentication authenticationRequest = authenticationCaptor.getValue();
		assertThat(authenticationRequest).isInstanceOf(UsernamePasswordAuthenticationToken.class);
		assertThat(authenticationRequest.getName()).isEqualTo("rod");
	}

	@Test
	public void doFilterWhenUsernameChangesAndNotUsernamePasswordAuthenticationTokenThenAuthenticationIsRequired()
			throws Exception {
		SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
		SecurityContext securityContext = securityContextHolderStrategy.createEmptyContext();
		Authentication authentication = new TestingAuthenticationToken("user", "password", "USER");
		securityContext.setAuthentication(authentication);
		securityContextHolderStrategy.setContext(securityContext);

		String token = "rod:koala";
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Basic " + CodecTestUtils.encodeBase64(token));
		FilterChain filterChain = mock(FilterChain.class);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(200);

		ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(this.manager).authenticate(authenticationCaptor.capture());
		verify(filterChain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		verifyNoMoreInteractions(this.manager, filterChain);

		Authentication authenticationRequest = authenticationCaptor.getValue();
		assertThat(authenticationRequest).isInstanceOf(UsernamePasswordAuthenticationToken.class);
		assertThat(authenticationRequest.getName()).isEqualTo("rod");
	}

	@Test
	public void doFilterWhenCustomAuthenticationConverterThatIgnoresRequestThenIgnores() throws Exception {
		this.filter.setAuthenticationConverter(new TestAuthenticationConverter());
		String token = "rod:koala";
		MockHttpServletRequest request = get("/ignored").build();
		request.addHeader("Authorization", "Basic " + CodecTestUtils.encodeBase64(token));
		FilterChain filterChain = mock(FilterChain.class);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(200);

		verify(this.manager, never()).authenticate(any(Authentication.class));
		verify(filterChain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		verifyNoMoreInteractions(this.manager, filterChain);
	}

	@Test
	void doFilterWhenAuthenticatedThenCombinesAuthorities() throws Exception {
		String ROLE_EXISTING = "ROLE_EXISTING";
		TestingAuthenticationToken existingAuthn = new TestingAuthenticationToken("username", "password",
				ROLE_EXISTING);
		SecurityContextHolder.setContext(new SecurityContextImpl(existingAuthn));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + CodecTestUtils.encodeBase64("a:b"));
		MockHttpServletResponse response = new MockHttpServletResponse();
		AuthenticationManager manager = mock(AuthenticationManager.class);
		given(manager.authenticate(any())).willReturn(new TestingAuthenticationToken("username", "password", "TEST"));
		BasicAuthenticationFilter filter = new BasicAuthenticationFilter(manager);
		filter.setMfaEnabled(true);
		filter.doFilter(request, response, new MockFilterChain());
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		assertThat(authentication.getAuthorities()).extracting(GrantedAuthority::getAuthority)
			.containsExactlyInAnyOrder(ROLE_EXISTING, "TEST");
	}

	@Test
	void doFilterWhenDefaultThenMfaDisabled() throws Exception {
		String ROLE_EXISTING = "ROLE_EXISTING";
		TestingAuthenticationToken existingAuthn = new TestingAuthenticationToken("username", "password",
				ROLE_EXISTING);
		SecurityContextHolder.setContext(new SecurityContextImpl(existingAuthn));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + CodecTestUtils.encodeBase64("a:b"));
		MockHttpServletResponse response = new MockHttpServletResponse();
		AuthenticationManager manager = mock(AuthenticationManager.class);
		TestingAuthenticationToken newAuthn = new TestingAuthenticationToken("username", "password", "TEST");
		given(manager.authenticate(any())).willReturn(newAuthn);
		BasicAuthenticationFilter filter = new BasicAuthenticationFilter(manager);
		filter.doFilter(request, response, new MockFilterChain());
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		assertThat(authentication).isEqualTo(newAuthn);
	}

	// gh-18112
	@Test
	void doFilterWhenDifferentPrincipalThenDoesNotCombine() throws Exception {
		String ROLE_EXISTING = "ROLE_EXISTING";
		TestingAuthenticationToken existingAuthn = new TestingAuthenticationToken("username", "password",
				ROLE_EXISTING);
		SecurityContextHolder.setContext(new SecurityContextImpl(existingAuthn));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + CodecTestUtils.encodeBase64("a:b"));
		MockHttpServletResponse response = new MockHttpServletResponse();
		AuthenticationManager manager = mock(AuthenticationManager.class);
		TestingAuthenticationToken newAuthn = new TestingAuthenticationToken(existingAuthn.getName() + "different",
				"password", "TEST");
		given(manager.authenticate(any())).willReturn(newAuthn);
		BasicAuthenticationFilter filter = new BasicAuthenticationFilter(manager);
		filter.setMfaEnabled(true);
		filter.doFilter(request, response, new MockFilterChain());
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		assertThat(authentication).isEqualTo(newAuthn);
	}

	/**
	 * This is critical to avoid adding duplicate GrantedAuthority instances with the
	 * same' authority when the issuedAt is too old and a new instance is requested.
	 * @throws Exception
	 */
	@Test
	void doFilterWhenDefaultEqualsGrantedAuthorityThenNoDuplicates() throws Exception {
		TestingAuthenticationToken existingAuthn = new TestingAuthenticationToken("username", "password",
				new DefaultEqualsGrantedAuthority());
		SecurityContextHolder.setContext(new SecurityContextImpl(existingAuthn));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + CodecTestUtils.encodeBase64("a:b"));
		MockHttpServletResponse response = new MockHttpServletResponse();
		AuthenticationManager manager = mock(AuthenticationManager.class);
		given(manager.authenticate(any()))
			.willReturn(new TestingAuthenticationToken("username", "password", new DefaultEqualsGrantedAuthority()));
		BasicAuthenticationFilter filter = new BasicAuthenticationFilter(manager);
		filter.doFilter(request, response, new MockFilterChain());
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		assertThat(new ArrayList<GrantedAuthority>(authentication.getAuthorities()))
			.extracting(GrantedAuthority::getAuthority)
			.containsExactly(DefaultEqualsGrantedAuthority.AUTHORITY);
	}

	@Test
	void doFilterWhenNotOverridingToBuilderThenDoesNotMergeAuthorities() throws Exception {
		TestingAuthenticationToken existingAuthn = new TestingAuthenticationToken("username", "password", "FACTORONE");
		SecurityContextHolder.setContext(new SecurityContextImpl(existingAuthn));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + CodecTestUtils.encodeBase64("a:b"));
		MockHttpServletResponse response = new MockHttpServletResponse();
		AuthenticationManager manager = mock(AuthenticationManager.class);
		given(manager.authenticate(any()))
			.willReturn(new NonBuildableAuthenticationToken("username", "password", "FACTORTWO"));
		BasicAuthenticationFilter filter = new BasicAuthenticationFilter(manager);
		filter.doFilter(request, response, new MockFilterChain());
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		SecurityAssertions.assertThat(authentication)
			.authorities()
			.extracting(GrantedAuthority::getAuthority)
			.containsExactly("FACTORTWO");
	}

	@Test
	public void doFilterWhenCustomAuthenticationConverterRequestThenAuthenticate() throws Exception {
		this.filter.setAuthenticationConverter(new TestAuthenticationConverter());
		String token = "rod:koala";
		MockHttpServletRequest request = get("/ok").build();
		request.addHeader("Authorization", "Basic " + CodecTestUtils.encodeBase64(token));
		FilterChain filterChain = mock(FilterChain.class);
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.filter.doFilter(request, response, filterChain);
		assertThat(response.getStatus()).isEqualTo(200);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("rod");
	}

	@Test
	void setCredentialsCharsetSynchronizesWithEntryPoint() {
		BasicAuthenticationEntryPoint entryPoint = new BasicAuthenticationEntryPoint();
		entryPoint.setRealmName("Test");
		BasicAuthenticationFilter filter = new BasicAuthenticationFilter(mock(AuthenticationManager.class), entryPoint);
		filter.setCredentialsCharset("ISO-8859-1");
		assertThat(entryPoint.getCharset()).isEqualTo(StandardCharsets.ISO_8859_1);
	}

	@Test
	public void setAuthenticationConverterWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.filter.setAuthenticationConverter(null));
	}

	static class TestAuthenticationConverter implements AuthenticationConverter {

		private final RequestMatcher matcher = pathPattern("/ignored");

		private final BasicAuthenticationConverter delegate = new BasicAuthenticationConverter();

		@Override
		public Authentication convert(HttpServletRequest request) {
			if (this.matcher.matches(request)) {
				return null;
			}
			return this.delegate.convert(request);
		}

	}

}
