/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.kerberos.web;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.kerberos.authentication.KerberosServiceRequestToken;
import org.springframework.security.kerberos.authentication.KerberosTicketValidation;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.SecurityContextRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Test class for {@link SpnegoAuthenticationProcessingFilter}
 *
 * @author Mike Wiesner
 * @author Jeremy Stone
 * @since 1.0
 */
public class SpnegoAuthenticationProcessingFilterTests {

	private SpnegoAuthenticationProcessingFilter filter;

	private AuthenticationManager authenticationManager;

	private HttpServletRequest request;

	private HttpServletResponse response;

	private FilterChain chain;

	private AuthenticationSuccessHandler successHandler;

	private AuthenticationFailureHandler failureHandler;

	private WebAuthenticationDetailsSource detailsSource;

	// data
	private static final byte[] TEST_TOKEN = "TestToken".getBytes();

	private static final String TEST_TOKEN_BASE64 = "VGVzdFRva2Vu";

	private static KerberosTicketValidation UNUSED_TICKET_VALIDATION = mock(KerberosTicketValidation.class);

	private static final Authentication AUTHENTICATION = new KerberosServiceRequestToken("test",
			UNUSED_TICKET_VALIDATION, AuthorityUtils.createAuthorityList("ROLE_ADMIN"), TEST_TOKEN);

	private static final String HEADER = "Authorization";

	private static final String TOKEN_PREFIX_NEG = "Negotiate ";

	private static final String TOKEN_PREFIX_KERB = "Kerberos ";

	private static final String TOKEN_NTLM = "Negotiate TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==";

	private static final BadCredentialsException BCE = new BadCredentialsException("");

	@BeforeEach
	public void before() throws Exception {
		// mocking
		this.authenticationManager = mock(AuthenticationManager.class);
		this.detailsSource = new WebAuthenticationDetailsSource();
		this.filter = new SpnegoAuthenticationProcessingFilter();
		this.filter.setAuthenticationManager(this.authenticationManager);
		this.request = mock(HttpServletRequest.class);
		this.response = mock(HttpServletResponse.class);
		this.chain = mock(FilterChain.class);
		this.filter.afterPropertiesSet();
	}

	@Test
	public void testEverythingWorks() throws Exception {
		everythingWorks(TOKEN_PREFIX_NEG);
	}

	@Test
	public void testEverythingWorks_Kerberos() throws Exception {
		everythingWorks(TOKEN_PREFIX_KERB);
	}

	@Test
	public void testEverythingWorksWithHandlers() throws Exception {
		everythingWorksWithHandlers(TOKEN_PREFIX_NEG);
	}

	@Test
	public void testEverythingWorksWithHandlers_Kerberos() throws Exception {
		everythingWorksWithHandlers(TOKEN_PREFIX_KERB);
	}

	private void everythingWorksWithHandlers(String tokenPrefix) throws Exception {
		createHandler();
		everythingWorks(tokenPrefix);
		everythingWorksVerifyHandlers();
	}

	private void everythingWorksVerifyHandlers() throws Exception {
		verify(this.successHandler).onAuthenticationSuccess(this.request, this.response, AUTHENTICATION);
		verify(this.failureHandler, never()).onAuthenticationFailure(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(AuthenticationException.class));
	}

	private void everythingWorks(String tokenPrefix) throws IOException, ServletException {
		// stubbing
		SecurityContextRepository securityContextRepository = mock(SecurityContextRepository.class);
		this.filter.setSecurityContextRepository(securityContextRepository);
		everythingWorksStub(tokenPrefix);

		// testing
		this.filter.doFilter(this.request, this.response, this.chain);
		verify(this.chain).doFilter(this.request, this.response);
		verify(securityContextRepository).saveContext(SecurityContextHolder.getContext(), this.request, this.response);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isEqualTo(AUTHENTICATION);
	}

	@Test
	public void testNoHeader() throws Exception {
		this.filter.doFilter(this.request, this.response, this.chain);
		// If the header is not present, the filter is not allowed to call
		// authenticate()
		verify(this.authenticationManager, never()).authenticate(any(Authentication.class));
		// chain should go on
		verify(this.chain).doFilter(this.request, this.response);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isEqualTo(null);
	}

	@Test
	public void testNTLMSSPHeader() throws Exception {
		given(this.request.getHeader(HEADER)).willReturn(TOKEN_NTLM);

		this.filter.doFilter(this.request, this.response, this.chain);
		// If the header is not present, the filter is not allowed to call
		// authenticate()
		verify(this.authenticationManager, never()).authenticate(any(Authentication.class));
		// chain should go on
		verify(this.chain).doFilter(this.request, this.response);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isEqualTo(null);
	}

	@Test
	public void testAuthenticationFails() throws Exception {
		authenticationFails();
		verify(this.response).setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
	}

	@Test
	public void testAuthenticationFailsWithHandlers() throws Exception {
		createHandler();
		authenticationFails();
		verify(this.failureHandler).onAuthenticationFailure(this.request, this.response, BCE);
		verify(this.successHandler, never()).onAuthenticationSuccess(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(Authentication.class));
		verify(this.response, never()).setStatus(anyInt());
	}

	@Test
	public void testAlreadyAuthenticated() throws Exception {
		try {
			Authentication existingAuth = new UsernamePasswordAuthenticationToken("mike", "mike",
					AuthorityUtils.createAuthorityList("ROLE_TEST"));
			SecurityContextHolder.getContext().setAuthentication(existingAuth);
			given(this.request.getHeader(HEADER)).willReturn(TOKEN_PREFIX_NEG + TEST_TOKEN_BASE64);
			this.filter.doFilter(this.request, this.response, this.chain);
			verify(this.authenticationManager, never()).authenticate(any(Authentication.class));
		}
		finally {
			SecurityContextHolder.clearContext();
		}
	}

	@Test
	public void testAlreadyAuthenticatedWithNotAuthenticatedToken() throws Exception {
		try {
			// this token is not authenticated yet!
			Authentication existingAuth = new UsernamePasswordAuthenticationToken("mike", "mike");
			SecurityContextHolder.getContext().setAuthentication(existingAuth);
			everythingWorks(TOKEN_PREFIX_NEG);
		}
		finally {
			SecurityContextHolder.clearContext();
		}
	}

	@Test
	public void testAlreadyAuthenticatedWithAnonymousToken() throws Exception {
		try {
			Authentication existingAuth = new AnonymousAuthenticationToken("test", "mike",
					AuthorityUtils.createAuthorityList("ROLE_TEST"));
			SecurityContextHolder.getContext().setAuthentication(existingAuth);
			everythingWorks(TOKEN_PREFIX_NEG);
		}
		finally {
			SecurityContextHolder.clearContext();
		}
	}

	@Test
	public void testAlreadyAuthenticatedNotActive() throws Exception {
		try {
			Authentication existingAuth = new UsernamePasswordAuthenticationToken("mike", "mike",
					AuthorityUtils.createAuthorityList("ROLE_TEST"));
			SecurityContextHolder.getContext().setAuthentication(existingAuth);
			this.filter.setSkipIfAlreadyAuthenticated(false);
			everythingWorks(TOKEN_PREFIX_NEG);
		}
		finally {
			SecurityContextHolder.clearContext();
		}
	}

	@Test
	public void testEverythingWorksWithHandlers_stopFilterChain() throws Exception {
		this.filter.setStopFilterChainOnSuccessfulAuthentication(true);

		createHandler();
		everythingWorksStub(TOKEN_PREFIX_NEG);

		// testing
		this.filter.doFilter(this.request, this.response, this.chain);
		verify(this.chain, never()).doFilter(this.request, this.response);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isEqualTo(AUTHENTICATION);
		everythingWorksVerifyHandlers();
	}

	private void everythingWorksStub(String tokenPrefix) throws IOException, ServletException {
		given(this.request.getHeader(HEADER)).willReturn(tokenPrefix + TEST_TOKEN_BASE64);
		KerberosServiceRequestToken requestToken = new KerberosServiceRequestToken(TEST_TOKEN);
		requestToken.setDetails(this.detailsSource.buildDetails(this.request));
		given(this.authenticationManager.authenticate(requestToken)).willReturn(AUTHENTICATION);
	}

	private void authenticationFails() throws IOException, ServletException {
		// stubbing
		given(this.request.getHeader(HEADER)).willReturn(TOKEN_PREFIX_NEG + TEST_TOKEN_BASE64);
		given(this.authenticationManager.authenticate(any(Authentication.class))).willThrow(BCE);

		// testing
		this.filter.doFilter(this.request, this.response, this.chain);
		// chain should stop here and it should send back a 500
		// future version should call some error handler
		verify(this.chain, never()).doFilter(any(ServletRequest.class), any(ServletResponse.class));
	}

	private void createHandler() {
		this.successHandler = mock(AuthenticationSuccessHandler.class);
		this.failureHandler = mock(AuthenticationFailureHandler.class);
		this.filter.setSuccessHandler(this.successHandler);
		this.filter.setFailureHandler(this.failureHandler);
	}

	@AfterEach
	public void after() {
		SecurityContextHolder.clearContext();
	}

}
