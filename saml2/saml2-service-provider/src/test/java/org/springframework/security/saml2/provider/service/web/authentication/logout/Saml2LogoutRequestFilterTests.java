/*
 * Copyright 2002-2022 the original author or authors.
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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link Saml2LogoutRequestFilter}
 */
public class Saml2LogoutRequestFilterTests {

	SecurityContextHolderStrategy securityContextHolderStrategy = mock(SecurityContextHolderStrategy.class);

	RelyingPartyRegistrationResolver relyingPartyRegistrationResolver = mock(RelyingPartyRegistrationResolver.class);

	Saml2LogoutRequestValidator logoutRequestValidator = mock(Saml2LogoutRequestValidator.class);

	LogoutHandler logoutHandler = mock(LogoutHandler.class);

	Saml2LogoutResponseResolver logoutResponseResolver = mock(Saml2LogoutResponseResolver.class);

	Saml2LogoutRequestFilter logoutRequestProcessingFilter = new Saml2LogoutRequestFilter(
			this.relyingPartyRegistrationResolver, this.logoutRequestValidator, this.logoutResponseResolver,
			this.logoutHandler);

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void doFilterWhenSamlRequestThenRedirects() throws Exception {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		request.setParameter(Saml2ParameterNames.SAML_REQUEST, "request");
		MockHttpServletResponse response = new MockHttpServletResponse();
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(registration);
		given(this.logoutRequestValidator.validate(any())).willReturn(Saml2LogoutValidatorResult.success());
		Saml2LogoutResponse logoutResponse = Saml2LogoutResponse.withRelyingPartyRegistration(registration)
				.samlResponse("response").build();
		given(this.logoutResponseResolver.resolve(any(), any())).willReturn(logoutResponse);
		this.logoutRequestProcessingFilter.doFilterInternal(request, response, new MockFilterChain());
		verify(this.logoutRequestValidator).validate(any());
		verify(this.logoutHandler).logout(any(), any(), any());
		verify(this.logoutResponseResolver).resolve(any(), any());
		String content = response.getHeader("Location");
		assertThat(content).contains(Saml2ParameterNames.SAML_RESPONSE);
		assertThat(content)
				.startsWith(registration.getAssertingPartyDetails().getSingleLogoutServiceResponseLocation());
	}

	@Test
	public void doFilterWhenSamlRequestThenPosts() throws Exception {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full()
				.assertingPartyDetails((party) -> party.singleLogoutServiceBinding(Saml2MessageBinding.POST)).build();
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		given(this.securityContextHolderStrategy.getContext()).willReturn(new SecurityContextImpl(authentication));
		this.logoutRequestProcessingFilter.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		request.setParameter(Saml2ParameterNames.SAML_REQUEST, "request");
		MockHttpServletResponse response = new MockHttpServletResponse();
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(registration);
		given(this.logoutRequestValidator.validate(any())).willReturn(Saml2LogoutValidatorResult.success());
		Saml2LogoutResponse logoutResponse = Saml2LogoutResponse.withRelyingPartyRegistration(registration)
				.samlResponse("response").build();
		given(this.logoutResponseResolver.resolve(any(), any())).willReturn(logoutResponse);
		this.logoutRequestProcessingFilter.doFilterInternal(request, response, new MockFilterChain());
		verify(this.logoutRequestValidator).validate(any());
		verify(this.logoutHandler).logout(any(), any(), any());
		verify(this.logoutResponseResolver).resolve(any(), any());
		String content = response.getContentAsString();
		assertThat(content).contains(Saml2ParameterNames.SAML_RESPONSE);
		assertThat(content).contains(registration.getAssertingPartyDetails().getSingleLogoutServiceResponseLocation());
		assertThat(content).contains(
				"<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'sha256-t+jmhLjs1ocvgaHBJsFcgznRk68d37TLtbI3NE9h7EU='\">");
		assertThat(content).contains("<script>window.onload = () => document.forms[0].submit();</script>");
		verify(this.securityContextHolderStrategy).getContext();
	}

	@Test
	public void doFilterWhenRequestMismatchesThenNoLogout() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
		request.setServletPath("/logout");
		request.setParameter(Saml2ParameterNames.SAML_RESPONSE, "response");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.logoutRequestProcessingFilter.doFilterInternal(request, response, new MockFilterChain());
		verifyNoInteractions(this.logoutRequestValidator, this.logoutHandler);
	}

	@Test
	public void doFilterWhenNoSamlRequestOrResponseThenNoLogout() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.logoutRequestProcessingFilter.doFilterInternal(request, response, new MockFilterChain());
		verifyNoInteractions(this.logoutRequestValidator, this.logoutHandler);
	}

	@Test
	public void doFilterWhenValidationFailsThen401() throws Exception {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		request.setParameter(Saml2ParameterNames.SAML_REQUEST, "request");
		MockHttpServletResponse response = new MockHttpServletResponse();
		given(this.relyingPartyRegistrationResolver.resolve(request, null)).willReturn(registration);
		given(this.logoutRequestValidator.validate(any()))
				.willReturn(Saml2LogoutValidatorResult.withErrors(new Saml2Error("error", "description")).build());
		this.logoutRequestProcessingFilter.doFilter(request, response, new MockFilterChain());
		assertThat(response.getStatus()).isEqualTo(401);
		verifyNoInteractions(this.logoutHandler);
	}

	@Test
	public void doFilterWhenNoRelyingPartyLogoutThen401() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		request.setParameter(Saml2ParameterNames.SAML_REQUEST, "request");
		MockHttpServletResponse response = new MockHttpServletResponse();
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().singleLogoutServiceLocation(null)
				.build();
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(registration);
		this.logoutRequestProcessingFilter.doFilterInternal(request, response, new MockFilterChain());
		assertThat(response.getStatus()).isEqualTo(401);
		verifyNoInteractions(this.logoutHandler);
	}

}
