/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import org.junit.After;
import org.junit.Test;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.mock;
import static org.mockito.BDDMockito.verify;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.verifyNoInteractions;

public class Saml2LogoutRequestFilterTests {

	private final LogoutHandler handler = mock(LogoutHandler.class);

	private final LogoutSuccessHandler successHandler = mock(LogoutSuccessHandler.class);

	private final Saml2LogoutRequestFilter filter = new Saml2LogoutRequestFilter(this.successHandler, this.handler);

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void doFilterWhenSamlRequestMatchesThenLogout() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		request.setParameter("SAMLRequest", "request");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.filter.doFilterInternal(request, response, new MockFilterChain());
		verify(this.handler).logout(request, response, authentication);
		verify(this.successHandler).onLogoutSuccess(request, response, authentication);
	}

	@Test
	public void doFilterWhenSamlResponseMatchesThenLogout() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		request.setParameter("SAMLRequest", "request");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.filter.doFilterInternal(request, response, new MockFilterChain());
		verify(this.handler).logout(request, response, authentication);
		verify(this.successHandler).onLogoutSuccess(request, response, authentication);
	}

	@Test
	public void doFilterWhenRequestMismatchesThenNoLogout() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
		request.setServletPath("/logout");
		request.setParameter("SAMLRequest", "request");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.filter.doFilterInternal(request, response, new MockFilterChain());
		verifyNoInteractions(this.handler);
		verifyNoInteractions(this.successHandler);
	}

	@Test
	public void doFilterWhenNoSamlRequestOrResponseThenNoLogout() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.filter.doFilterInternal(request, response, new MockFilterChain());
		verifyNoInteractions(this.handler);
		verifyNoInteractions(this.successHandler);
	}

	@Test
	public void doFilterWhenLogoutHandlerFailsThenNoSuccessHandler() {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		request.setParameter("SAMLRequest", "request");
		MockHttpServletResponse response = new MockHttpServletResponse();
		willThrow(RuntimeException.class).given(this.handler).logout(request, response, authentication);
		assertThatExceptionOfType(RuntimeException.class)
				.isThrownBy(() -> this.filter.doFilterInternal(request, response, new MockFilterChain()));
		verify(this.handler).logout(request, response, authentication);
		verifyNoInteractions(this.successHandler);
	}

}
