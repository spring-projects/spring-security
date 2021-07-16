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
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutAuthenticatorResult;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestAuthenticator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseResolver.Saml2LogoutResponseBuilder;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.mock;
import static org.mockito.BDDMockito.verify;
import static org.mockito.BDDMockito.willReturn;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link Saml2LogoutRequestFilter}
 */
public class Saml2LogoutRequestFilterTests {

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver = mock(
			RelyingPartyRegistrationResolver.class);

	private final Saml2LogoutRequestAuthenticator manager = mock(Saml2LogoutRequestAuthenticator.class);

	private final LogoutHandler handler = mock(LogoutHandler.class);

	private final Saml2LogoutResponseResolver logoutResponseResolver = mock(Saml2LogoutResponseResolver.class);

	private final Saml2LogoutRequestFilter filter = new Saml2LogoutRequestFilter(this.relyingPartyRegistrationResolver,
			this.manager, this.handler, this.logoutResponseResolver);

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void doFilterWhenSamlRequestMatchesThenRedirects() throws Exception {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		request.setParameter("SAMLRequest", "request");
		MockHttpServletResponse response = new MockHttpServletResponse();
		given(this.relyingPartyRegistrationResolver.resolve(request, null)).willReturn(registration);
		given(this.manager.authenticate(any())).willReturn(Saml2LogoutAuthenticatorResult.success());
		Saml2LogoutResponse logoutResponse = Saml2LogoutResponse.withRelyingPartyRegistration(registration)
				.samlResponse("response").build();
		Saml2LogoutResponseBuilder<?> partial = mock(Saml2LogoutResponseBuilder.class, RETURNS_SELF);
		given(partial.logoutResponse()).willReturn(logoutResponse);
		willReturn(partial).given(this.logoutResponseResolver).resolveLogoutResponse(request, authentication);
		this.filter.doFilterInternal(request, response, new MockFilterChain());
		verify(this.handler).logout(any(), any(), any());
		verify(this.logoutResponseResolver).resolveLogoutResponse(any(), any());
		String content = response.getHeader("Location");
		assertThat(content).contains("SAMLResponse");
		assertThat(content)
				.startsWith(registration.getAssertingPartyDetails().getSingleLogoutServiceResponseLocation());
	}

	@Test
	public void doFilterWhenSamlRequestMatchesThenPosts() throws Exception {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full()
				.assertingPartyDetails((party) -> party.singleLogoutServiceBinding(Saml2MessageBinding.POST)).build();
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		request.setParameter("SAMLRequest", "request");
		MockHttpServletResponse response = new MockHttpServletResponse();
		given(this.relyingPartyRegistrationResolver.resolve(request, null)).willReturn(registration);
		given(this.manager.authenticate(any())).willReturn(Saml2LogoutAuthenticatorResult.success());
		Saml2LogoutResponse logoutResponse = Saml2LogoutResponse.withRelyingPartyRegistration(registration)
				.samlResponse("response").build();
		Saml2LogoutResponseBuilder<?> partial = mock(Saml2LogoutResponseBuilder.class, RETURNS_SELF);
		given(partial.logoutResponse()).willReturn(logoutResponse);
		willReturn(partial).given(this.logoutResponseResolver).resolveLogoutResponse(request, authentication);
		this.filter.doFilterInternal(request, response, new MockFilterChain());
		verify(this.handler).logout(any(), any(), any());
		verify(this.logoutResponseResolver).resolveLogoutResponse(any(), any());
		String content = response.getContentAsString();
		assertThat(content).contains("SAMLResponse");
		assertThat(content).contains(registration.getAssertingPartyDetails().getSingleLogoutServiceResponseLocation());
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
		verifyNoInteractions(this.manager);
		verifyNoInteractions(this.handler);
		verifyNoInteractions(this.logoutResponseResolver);
	}

	@Test
	public void doFilterWhenNoSamlRequestOrResponseThenNoLogout() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.filter.doFilterInternal(request, response, new MockFilterChain());
		verifyNoInteractions(this.manager);
		verifyNoInteractions(this.handler);
		verifyNoInteractions(this.logoutResponseResolver);
	}

	@Test
	public void doFilterWhenAuthenticationManagerFailsThenNoLogout() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		request.setParameter("SAMLRequest", "request");
		MockHttpServletResponse response = new MockHttpServletResponse();
		given(this.relyingPartyRegistrationResolver.resolve(request, null)).willReturn(registration);
		willThrow(Saml2Exception.class).given(this.manager).authenticate(any());
		assertThatExceptionOfType(Saml2Exception.class)
				.isThrownBy(() -> this.filter.doFilterInternal(request, response, new MockFilterChain()));
		verifyNoInteractions(this.handler);
		verifyNoInteractions(this.logoutResponseResolver);
	}

}
