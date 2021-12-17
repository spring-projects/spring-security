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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponseValidator;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutValidatorResult;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.mock;
import static org.mockito.BDDMockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link Saml2LogoutResponseFilter}
 */
public class Saml2LogoutResponseFilterTests {

	RelyingPartyRegistrationResolver relyingPartyRegistrationResolver = mock(RelyingPartyRegistrationResolver.class);

	Saml2LogoutRequestRepository logoutRequestRepository = mock(Saml2LogoutRequestRepository.class);

	Saml2LogoutResponseValidator logoutResponseValidator = mock(Saml2LogoutResponseValidator.class);

	LogoutSuccessHandler logoutSuccessHandler = mock(LogoutSuccessHandler.class);

	Saml2LogoutResponseFilter logoutResponseProcessingFilter = new Saml2LogoutResponseFilter(
			this.relyingPartyRegistrationResolver, this.logoutResponseValidator, this.logoutSuccessHandler);

	@BeforeEach
	public void setUp() {
		this.logoutResponseProcessingFilter.setLogoutRequestRepository(this.logoutRequestRepository);
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void doFilterWhenSamlResponsePostThenLogout() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		request.setParameter(Saml2ParameterNames.SAML_RESPONSE, "response");
		MockHttpServletResponse response = new MockHttpServletResponse();
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		given(this.relyingPartyRegistrationResolver.resolve(request, "registration-id")).willReturn(registration);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest("request").build();
		given(this.logoutRequestRepository.removeLogoutRequest(request, response)).willReturn(logoutRequest);
		given(this.logoutResponseValidator.validate(any())).willReturn(Saml2LogoutValidatorResult.success());
		this.logoutResponseProcessingFilter.doFilterInternal(request, response, new MockFilterChain());
		verify(this.logoutResponseValidator).validate(any());
		verify(this.logoutSuccessHandler).onLogoutSuccess(any(), any(), any());
	}

	@Test
	public void doFilterWhenSamlResponseRedirectThenLogout() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		request.setParameter(Saml2ParameterNames.SAML_RESPONSE, "response");
		MockHttpServletResponse response = new MockHttpServletResponse();
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full()
				.singleLogoutServiceBinding(Saml2MessageBinding.REDIRECT).build();
		given(this.relyingPartyRegistrationResolver.resolve(request, "registration-id")).willReturn(registration);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest("request").build();
		given(this.logoutRequestRepository.removeLogoutRequest(request, response)).willReturn(logoutRequest);
		given(this.logoutResponseValidator.validate(any())).willReturn(Saml2LogoutValidatorResult.success());
		this.logoutResponseProcessingFilter.doFilterInternal(request, response, new MockFilterChain());
		verify(this.logoutResponseValidator).validate(any());
		verify(this.logoutSuccessHandler).onLogoutSuccess(any(), any(), any());
	}

	@Test
	public void doFilterWhenRequestMismatchesThenNoLogout() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout");
		request.setServletPath("/logout");
		request.setParameter(Saml2ParameterNames.SAML_REQUEST, "request");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.logoutResponseProcessingFilter.doFilterInternal(request, response, new MockFilterChain());
		verifyNoInteractions(this.logoutResponseValidator, this.logoutSuccessHandler);
	}

	@Test
	public void doFilterWhenNoSamlRequestOrResponseThenNoLogout() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		MockHttpServletResponse response = new MockHttpServletResponse();
		this.logoutResponseProcessingFilter.doFilterInternal(request, response, new MockFilterChain());
		verifyNoInteractions(this.logoutResponseValidator, this.logoutSuccessHandler);
	}

	@Test
	public void doFilterWhenValidatorFailsThenStops() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		request.setParameter(Saml2ParameterNames.SAML_RESPONSE, "response");
		MockHttpServletResponse response = new MockHttpServletResponse();
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		given(this.relyingPartyRegistrationResolver.resolve(request, "registration-id")).willReturn(registration);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest("request").build();
		given(this.logoutRequestRepository.removeLogoutRequest(request, response)).willReturn(logoutRequest);
		given(this.logoutResponseValidator.validate(any()))
				.willReturn(Saml2LogoutValidatorResult.withErrors(new Saml2Error("error", "description")).build());
		this.logoutResponseProcessingFilter.doFilterInternal(request, response, new MockFilterChain());
		verify(this.logoutResponseValidator).validate(any());
		verifyNoInteractions(this.logoutSuccessHandler);
	}

	@Test
	public void doFilterWhenNoRelyingPartyLogoutThen401() throws Exception {
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/logout/saml2/slo");
		request.setServletPath("/logout/saml2/slo");
		request.setParameter(Saml2ParameterNames.SAML_RESPONSE, "response");
		MockHttpServletResponse response = new MockHttpServletResponse();
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().singleLogoutServiceLocation(null)
				.singleLogoutServiceResponseLocation(null).build();
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(registration);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest("request").build();
		given(this.logoutRequestRepository.removeLogoutRequest(request, response)).willReturn(logoutRequest);
		this.logoutResponseProcessingFilter.doFilterInternal(request, response, new MockFilterChain());
		assertThat(response.getStatus()).isEqualTo(401);
		verifyNoInteractions(this.logoutSuccessHandler);
	}

}
