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

package org.springframework.security.cas.web;

import javax.servlet.FilterChain;

import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.junit.After;
import org.junit.Test;

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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.verifyZeroInteractions;

/**
 * Tests {@link CasAuthenticationFilter}.
 *
 * @author Ben Alex
 * @author Rob Winch
 */
public class CasAuthenticationFilterTests {

	@After
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

	@Test(expected = AuthenticationException.class)
	public void testNullServiceTicketHandledGracefully() throws Exception {
		CasAuthenticationFilter filter = new CasAuthenticationFilter();
		filter.setAuthenticationManager((a) -> {
			throw new BadCredentialsException("Rejected");
		});
		filter.attemptAuthentication(new MockHttpServletRequest(), new MockHttpServletResponse());
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
		SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken("key", "principal",
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
		verifyZeroInteractions(successHandler);
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
		verifyZeroInteractions(chain);
	}

}
