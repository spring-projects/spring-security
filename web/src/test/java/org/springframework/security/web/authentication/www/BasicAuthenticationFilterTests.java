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
import java.util.Arrays;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.switchuser.SwitchUserGrantedAuthority;
import org.springframework.web.util.WebUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Tests {@link BasicAuthenticationFilter}.
 *
 * @author Ben Alex
 */
public class BasicAuthenticationFilterTests {

	private BasicAuthenticationFilter filter;

	private AuthenticationManager manager;

	@Before
	public void setUp() {
		SecurityContextHolder.clearContext();
		UsernamePasswordAuthenticationToken rodRequest = new UsernamePasswordAuthenticationToken("rod", "koala");
		rodRequest.setDetails(new WebAuthenticationDetails(new MockHttpServletRequest()));
		Authentication rod = new UsernamePasswordAuthenticationToken("rod", "koala",
				AuthorityUtils.createAuthorityList("ROLE_1"));
		this.manager = mock(AuthenticationManager.class);
		given(this.manager.authenticate(rodRequest)).willReturn(rod);
		given(this.manager.authenticate(not(eq(rodRequest)))).willThrow(new BadCredentialsException(""));
		this.filter = new BasicAuthenticationFilter(this.manager, new BasicAuthenticationEntryPoint());
	}

	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testFilterIgnoresRequestsContainingNoAuthorizationHeader() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath("/some_file.html");
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
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Basic " + new String(Base64.encodeBase64(token.getBytes())));
		request.setServletPath("/some_file.html");
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
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Basic NOT_VALID_BASE64");
		request.setServletPath("/some_file.html");
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
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Basic " + new String(Base64.encodeBase64(token.getBytes())));
		request.setServletPath("/some_file.html");
		// Test
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, new MockHttpServletResponse(), chain);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("rod");
	}

	// gh-5586
	@Test
	public void doFilterWhenSchemeLowercaseThenCaseInsensitveMatchWorks() throws Exception {
		String token = "rod:koala";
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "basic " + new String(Base64.encodeBase64(token.getBytes())));
		request.setServletPath("/some_file.html");
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
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "BaSiC " + new String(Base64.encodeBase64(token.getBytes())));
		request.setServletPath("/some_file.html");
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, new MockHttpServletResponse(), chain);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("rod");
	}

	@Test
	public void testOtherAuthorizationSchemeIsIgnored() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "SOME_OTHER_AUTHENTICATION_SCHEME");
		request.setServletPath("/some_file.html");
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
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Basic " + new String(Base64.encodeBase64(token.getBytes())));
		request.setServletPath("/some_file.html");
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
		request.addHeader("Authorization", "Basic " + new String(Base64.encodeBase64(token.getBytes())));
		final MockHttpServletResponse response2 = new MockHttpServletResponse();
		chain = mock(FilterChain.class);
		this.filter.doFilter(request, response2, chain);
		verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		request.setServletPath("/some_file.html");
		// Test - the filter chain will not be invoked, as we get a 401 forbidden response
		MockHttpServletResponse response = response2;
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void testWrongPasswordContinuesFilterChainIfIgnoreFailureIsTrue() throws Exception {
		String token = "rod:WRONG_PASSWORD";
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Basic " + new String(Base64.encodeBase64(token.getBytes())));
		request.setServletPath("/some_file.html");
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
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Basic " + new String(Base64.encodeBase64(token.getBytes())));
		request.setServletPath("/some_file.html");
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
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Basic " + new String(Base64.encodeBase64(token.getBytes())));
		request.setServletPath("/some_file.html");
		request.setAttribute(WebUtils.ERROR_REQUEST_URI_ATTRIBUTE, "/error");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, response, chain);
		assertThat(response.getStatus()).isEqualTo(200);
	}

	@Test
	public void doFilterWhenTokenAndFilterCharsetMatchDefaultThenAuthenticated() throws Exception {
		SecurityContextHolder.clearContext();
		UsernamePasswordAuthenticationToken rodRequest = new UsernamePasswordAuthenticationToken("rod", "äöü");
		rodRequest.setDetails(new WebAuthenticationDetails(new MockHttpServletRequest()));
		Authentication rod = new UsernamePasswordAuthenticationToken("rod", "äöü",
				AuthorityUtils.createAuthorityList("ROLE_1"));
		this.manager = mock(AuthenticationManager.class);
		given(this.manager.authenticate(rodRequest)).willReturn(rod);
		given(this.manager.authenticate(not(eq(rodRequest)))).willThrow(new BadCredentialsException(""));
		this.filter = new BasicAuthenticationFilter(this.manager, new BasicAuthenticationEntryPoint());
		String token = "rod:äöü";
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization",
				"Basic " + new String(Base64.encodeBase64(token.getBytes(StandardCharsets.UTF_8))));
		request.setServletPath("/some_file.html");
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
		UsernamePasswordAuthenticationToken rodRequest = new UsernamePasswordAuthenticationToken("rod", "äöü");
		rodRequest.setDetails(new WebAuthenticationDetails(new MockHttpServletRequest()));
		Authentication rod = new UsernamePasswordAuthenticationToken("rod", "äöü",
				AuthorityUtils.createAuthorityList("ROLE_1"));
		this.manager = mock(AuthenticationManager.class);
		given(this.manager.authenticate(rodRequest)).willReturn(rod);
		given(this.manager.authenticate(not(eq(rodRequest)))).willThrow(new BadCredentialsException(""));
		this.filter = new BasicAuthenticationFilter(this.manager, new BasicAuthenticationEntryPoint());
		this.filter.setCredentialsCharset("ISO-8859-1");
		String token = "rod:äöü";
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization",
				"Basic " + new String(Base64.encodeBase64(token.getBytes(StandardCharsets.ISO_8859_1))));
		request.setServletPath("/some_file.html");
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
	public void doFilterWhenTokenAndFilterCharsetDoNotMatchThenUnauthorized() throws Exception {
		SecurityContextHolder.clearContext();
		UsernamePasswordAuthenticationToken rodRequest = new UsernamePasswordAuthenticationToken("rod", "äöü");
		rodRequest.setDetails(new WebAuthenticationDetails(new MockHttpServletRequest()));
		Authentication rod = new UsernamePasswordAuthenticationToken("rod", "äöü",
				AuthorityUtils.createAuthorityList("ROLE_1"));
		this.manager = mock(AuthenticationManager.class);
		given(this.manager.authenticate(rodRequest)).willReturn(rod);
		given(this.manager.authenticate(not(eq(rodRequest)))).willThrow(new BadCredentialsException(""));
		this.filter = new BasicAuthenticationFilter(this.manager, new BasicAuthenticationEntryPoint());
		this.filter.setCredentialsCharset("ISO-8859-1");
		String token = "rod:äöü";
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization",
				"Basic " + new String(Base64.encodeBase64(token.getBytes(StandardCharsets.UTF_8))));
		request.setServletPath("/some_file.html");
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
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Basic ");
		request.setServletPath("/some_file.html");
		request.setSession(new MockHttpSession());
		final MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, response, chain);
		verify(chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void whenSwitchedCheckOriginalUser() throws Exception {
		// prepare the saved switch-user token
		Authentication rodToken = new UsernamePasswordAuthenticationToken("rod", "koala",
				AuthorityUtils.createAuthorityList("ROLE_1"));
		UsernamePasswordAuthenticationToken switchedToken = new UsernamePasswordAuthenticationToken("switched", "user",
				Arrays.asList(new SwitchUserGrantedAuthority("PREVIOUS_ADMINISTRATOR", rodToken)));
		SecurityContextHolder.getContext().setAuthentication(switchedToken);
		// setup for test
		String token = "rod:koala";
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Basic " + new String(Base64.encodeBase64(token.getBytes())));
		request.setServletPath("/some_file.html");
		final MockHttpServletResponse response1 = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		this.filter.doFilter(request, response1, chain);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("switched");
	}

}
