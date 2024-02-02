/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.cas.web;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpSession;
import org.apereo.cas.client.proxy.ProxyGrantingTicketStorage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests {@link CasAuthenticationFilter}.
 *
 * @author Ben Alex
 * @author Rob Winch
 */
public class CasAuthenticationFilterTests {

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testGettersSetters() {
		CasAuthenticationFilter filter = new CasAuthenticationFilter();
		filter.setProxyGrantingTicketStorage(mock(ProxyGrantingTicketStorage.class));
		filter.setProxyReceptorUrl("/someurl");
		filter.setServiceProperties(new ServiceProperties());
	}

	@Test
	public void testNormalOperation() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath("/login/cas");
		request.addParameter("ticket", "ST-0-ER94xMJmn6pha35CQRoZ");
		CasAuthenticationFilter filter = new CasAuthenticationFilter();
		filter.setAuthenticationManager((a) -> a);
		assertThat(filter.requiresAuthentication(request, new MockHttpServletResponse())).isTrue();
		Authentication result = filter.attemptAuthentication(request, new MockHttpServletResponse());
		assertThat(result != null).isTrue();
	}

	@Test
	public void testNullServiceTicketHandledGracefully() throws Exception {
		CasAuthenticationFilter filter = new CasAuthenticationFilter();
		filter.setAuthenticationManager((a) -> {
			throw new BadCredentialsException("Rejected");
		});
		assertThatExceptionOfType(AuthenticationException.class).isThrownBy(
				() -> filter.attemptAuthentication(new MockHttpServletRequest(), new MockHttpServletResponse()));
	}

	@Test
	public void testRequiresAuthenticationFilterProcessUrl() {
		String url = "/login/cas";
		CasAuthenticationFilter filter = new CasAuthenticationFilter();
		filter.setFilterProcessesUrl(url);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		request.setServletPath(url);
		assertThat(filter.requiresAuthentication(request, response)).isTrue();
	}

	@Test
	public void testRequiresAuthenticationProxyRequest() {
		CasAuthenticationFilter filter = new CasAuthenticationFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		request.setServletPath("/pgtCallback");
		assertThat(filter.requiresAuthentication(request, response)).isFalse();
		filter.setProxyReceptorUrl(request.getServletPath());
		assertThat(filter.requiresAuthentication(request, response)).isFalse();
		filter.setProxyGrantingTicketStorage(mock(ProxyGrantingTicketStorage.class));
		assertThat(filter.requiresAuthentication(request, response)).isTrue();
		request.setServletPath("/other");
		assertThat(filter.requiresAuthentication(request, response)).isFalse();
	}

	@Test
	public void testRequiresAuthenticationAuthAll() {
		ServiceProperties properties = new ServiceProperties();
		properties.setAuthenticateAllArtifacts(true);
		String url = "/login/cas";
		CasAuthenticationFilter filter = new CasAuthenticationFilter();
		filter.setFilterProcessesUrl(url);
		filter.setServiceProperties(properties);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		request.setServletPath(url);
		assertThat(filter.requiresAuthentication(request, response)).isTrue();
		request.setServletPath("/other");
		assertThat(filter.requiresAuthentication(request, response)).isFalse();
		request.setParameter(properties.getArtifactParameter(), "value");
		assertThat(filter.requiresAuthentication(request, response)).isTrue();
		SecurityContextHolder.getContext()
			.setAuthentication(new AnonymousAuthenticationToken("key", "principal",
					AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
		assertThat(filter.requiresAuthentication(request, response)).isTrue();
		SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("un", "principal"));
		assertThat(filter.requiresAuthentication(request, response)).isTrue();
		SecurityContextHolder.getContext()
			.setAuthentication(new TestingAuthenticationToken("un", "principal", "ROLE_ANONYMOUS"));
		assertThat(filter.requiresAuthentication(request, response)).isFalse();
	}

	@Test
	public void testAuthenticateProxyUrl() throws Exception {
		CasAuthenticationFilter filter = new CasAuthenticationFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		request.setServletPath("/pgtCallback");
		filter.setProxyGrantingTicketStorage(mock(ProxyGrantingTicketStorage.class));
		filter.setProxyReceptorUrl(request.getServletPath());
		assertThat(filter.attemptAuthentication(request, response)).isNull();
	}

	@Test
	public void testDoFilterAuthenticateAll() throws Exception {
		AuthenticationSuccessHandler successHandler = mock(AuthenticationSuccessHandler.class);
		AuthenticationManager manager = mock(AuthenticationManager.class);
		Authentication authentication = new TestingAuthenticationToken("un", "pwd", "ROLE_USER");
		given(manager.authenticate(any(Authentication.class))).willReturn(authentication);
		ServiceProperties serviceProperties = new ServiceProperties();
		serviceProperties.setAuthenticateAllArtifacts(true);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter("ticket", "ST-1-123");
		request.setServletPath("/authenticate");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		CasAuthenticationFilter filter = new CasAuthenticationFilter();
		filter.setServiceProperties(serviceProperties);
		filter.setAuthenticationSuccessHandler(successHandler);
		filter.setProxyGrantingTicketStorage(mock(ProxyGrantingTicketStorage.class));
		filter.setAuthenticationManager(manager);
		filter.afterPropertiesSet();
		filter.doFilter(request, response, chain);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull()
			.withFailMessage("Authentication should not be null");
		verify(chain).doFilter(request, response);
		verifyNoInteractions(successHandler);
		// validate for when the filterProcessUrl matches
		filter.setFilterProcessesUrl(request.getServletPath());
		SecurityContextHolder.clearContext();
		filter.doFilter(request, response, chain);
		verifyNoMoreInteractions(chain);
		verify(successHandler).onAuthenticationSuccess(request, response, authentication);
	}

	// SEC-1592
	@Test
	public void testChainNotInvokedForProxyReceptor() throws Exception {
		CasAuthenticationFilter filter = new CasAuthenticationFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = mock(FilterChain.class);
		request.setServletPath("/pgtCallback");
		filter.setProxyGrantingTicketStorage(mock(ProxyGrantingTicketStorage.class));
		filter.setProxyReceptorUrl(request.getServletPath());
		filter.doFilter(request, response, chain);
		verifyNoInteractions(chain);
	}

	@Test
	public void successfulAuthenticationWhenProxyRequestThenSavesSecurityContext() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter(ServiceProperties.DEFAULT_CAS_ARTIFACT_PARAMETER, "ticket");

		MockHttpServletResponse response = new MockHttpServletResponse();
		CasAuthenticationFilter filter = new CasAuthenticationFilter();
		ServiceProperties serviceProperties = new ServiceProperties();
		serviceProperties.setAuthenticateAllArtifacts(true);
		filter.setServiceProperties(serviceProperties);

		SecurityContextRepository securityContextRepository = mock(SecurityContextRepository.class);
		ReflectionTestUtils.setField(filter, "securityContextRepository", securityContextRepository);

		filter.successfulAuthentication(request, response, new MockFilterChain(), mock(Authentication.class));
		verify(securityContextRepository).saveContext(any(SecurityContext.class), eq(request), eq(response));
	}

	@Test
	public void attemptAuthenticationWhenNoServiceTicketAndIsGatewayRequestThenRedirectToSavedRequestAndClearAttribute()
			throws Exception {
		CasAuthenticationFilter filter = new CasAuthenticationFilter();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		HttpSession session = request.getSession(true);
		session.setAttribute(CasGatewayAuthenticationRedirectFilter.CAS_GATEWAY_AUTHENTICATION_ATTR, true);

		new HttpSessionRequestCache().saveRequest(request, response);

		Authentication authn = filter.attemptAuthentication(request, response);
		assertThat(authn).isNull();
		assertThat(response.getStatus()).isEqualTo(302);
		assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost?continue");
		assertThat(session.getAttribute(CasGatewayAuthenticationRedirectFilter.CAS_GATEWAY_AUTHENTICATION_ATTR))
			.isNull();
	}

	@Test
	void successfulAuthenticationWhenSecurityContextRepositorySetThenUses() throws ServletException, IOException {
		SecurityContextRepository securityContextRepository = mock(SecurityContextRepository.class);
		CasAuthenticationFilter filter = new CasAuthenticationFilter();
		filter.setSecurityContextRepository(securityContextRepository);
		filter.successfulAuthentication(new MockHttpServletRequest(), new MockHttpServletResponse(),
				new MockFilterChain(), mock(Authentication.class));
		verify(securityContextRepository).saveContext(any(SecurityContext.class), any(), any());
	}

	@Test
	void successfulAuthenticationWhenSecurityContextHolderStrategySetThenUses() throws ServletException, IOException {
		SecurityContextHolderStrategy securityContextRepository = mock(SecurityContextHolderStrategy.class);
		given(securityContextRepository.createEmptyContext()).willReturn(new SecurityContextImpl());
		CasAuthenticationFilter filter = new CasAuthenticationFilter();
		filter.setSecurityContextHolderStrategy(securityContextRepository);
		filter.successfulAuthentication(new MockHttpServletRequest(), new MockHttpServletResponse(),
				new MockFilterChain(), mock(Authentication.class));
		verify(securityContextRepository).setContext(any(SecurityContext.class));
	}

}
