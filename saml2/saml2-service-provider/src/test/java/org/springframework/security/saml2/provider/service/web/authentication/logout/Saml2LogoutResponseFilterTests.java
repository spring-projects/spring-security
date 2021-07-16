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
import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseAuthenticator;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.mock;
import static org.mockito.BDDMockito.verify;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link Saml2LogoutResponseFilter}
 */
public class Saml2LogoutResponseFilterTests {

	private final RelyingPartyRegistrationResolver resolver = mock(RelyingPartyRegistrationResolver.class);

	private final Saml2LogoutRequestRepository repository = mock(Saml2LogoutRequestRepository.class);

	private final Saml2LogoutResponseAuthenticator manager = mock(Saml2LogoutResponseAuthenticator.class);

	private final LogoutSuccessHandler successHandler = mock(LogoutSuccessHandler.class);

	private final Saml2LogoutResponseFilter filter = new Saml2LogoutResponseFilter(this.resolver, this.manager);

	@Before
	public void setUp() {
		this.filter.setLogoutRequestRepository(this.repository);
		this.filter.setLogoutSuccessHandler(this.successHandler);
	}

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void doFilterWhenSamlResponsePostThenLogout() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		request.setParameter("SAMLResponse", "response");
		MockHttpServletResponse response = new MockHttpServletResponse();
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		given(this.resolver.resolve(request, "registration-id")).willReturn(registration);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest("request").build();
		given(this.repository.removeLogoutRequest(request, response)).willReturn(logoutRequest);
		this.filter.doFilterInternal(request, response, new MockFilterChain());
		verify(this.manager).authenticate(any());
		verify(this.successHandler).onLogoutSuccess(any(), any(), any());
	}

	@Test
	public void doFilterWhenSamlResponseRedirectThenLogout() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		request.setParameter("SAMLResponse", "response");
		MockHttpServletResponse response = new MockHttpServletResponse();
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		given(this.resolver.resolve(request, "registration-id")).willReturn(registration);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest("request").build();
		given(this.repository.removeLogoutRequest(request, response)).willReturn(logoutRequest);
		this.filter.doFilterInternal(request, response, new MockFilterChain());
		verify(this.manager).authenticate(any());
		verify(this.successHandler).onLogoutSuccess(any(), any(), any());
	}

	@Test
	public void doFilterWhenRequestMismatchesThenNoLogout() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
		request.setServletPath("/logout");
		request.setParameter("SAMLResponse", "response");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.filter.doFilterInternal(request, response, new MockFilterChain());
		verifyNoInteractions(this.manager);
		verifyNoInteractions(this.successHandler);
	}

	@Test
	public void doFilterWhenNoSamlRequestOrResponseThenNoLogout() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.filter.doFilterInternal(request, response, new MockFilterChain());
		verifyNoInteractions(this.manager);
		verifyNoInteractions(this.successHandler);
	}

	@Test
	public void doFilterWhenLogoutHandlerFailsThenNoSuccessHandler() {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		request.setParameter("SAMLResponse", "response");
		MockHttpServletResponse response = new MockHttpServletResponse();
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		given(this.resolver.resolve(request, "registration-id")).willReturn(registration);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest("request").build();
		given(this.repository.removeLogoutRequest(request, response)).willReturn(logoutRequest);
		willThrow(Saml2Exception.class).given(this.manager).authenticate(any());
		assertThatExceptionOfType(Saml2Exception.class)
				.isThrownBy(() -> this.filter.doFilterInternal(request, response, new MockFilterChain()));
		verify(this.manager).authenticate(any());
		verifyNoInteractions(this.successHandler);
	}

}
