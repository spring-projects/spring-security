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

package org.springframework.security.saml2.provider.service.web.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class OpenSaml4AuthenticationRequestResolverTests {

	MockHttpServletRequest request;

	RelyingPartyRegistration registration;

	@BeforeEach
	void setup() {
		this.request = givenRequest("/saml2/authenticate/registration-id");
		this.registration = TestRelyingPartyRegistrations.full().build();
	}

	@Test
	void resolveWhenRedirectThenSaml2RedirectAuthenticationRequest() {
		RelyingPartyRegistrationResolver relyingParties = mock(RelyingPartyRegistrationResolver.class);
		given(relyingParties.resolve(any(), any())).willReturn(this.registration);
		OpenSaml4AuthenticationRequestResolver resolver = new OpenSaml4AuthenticationRequestResolver(relyingParties);
		Saml2RedirectAuthenticationRequest authnRequest = resolver.resolve(this.request);
		assertThat(authnRequest.getBinding()).isEqualTo(Saml2MessageBinding.REDIRECT);
		assertThat(authnRequest.getAuthenticationRequestUri())
				.isEqualTo(this.registration.getAssertingPartyDetails().getSingleSignOnServiceLocation());
	}

	@Test
	void resolveWhenPostThenSaml2PostAuthenticationRequest() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full()
				.assertingPartyDetails((party) -> party.singleSignOnServiceBinding(Saml2MessageBinding.POST)).build();
		RelyingPartyRegistrationResolver relyingParties = mock(RelyingPartyRegistrationResolver.class);
		given(relyingParties.resolve(any(), any())).willReturn(registration);
		OpenSaml4AuthenticationRequestResolver resolver = new OpenSaml4AuthenticationRequestResolver(relyingParties);
		Saml2PostAuthenticationRequest authnRequest = resolver.resolve(this.request);
		assertThat(authnRequest.getBinding()).isEqualTo(Saml2MessageBinding.POST);
		assertThat(authnRequest.getAuthenticationRequestUri())
				.isEqualTo(this.registration.getAssertingPartyDetails().getSingleSignOnServiceLocation());
	}

	@Test
	void resolveWhenCustomRelayStateThenUses() {
		RelyingPartyRegistrationResolver relyingParties = mock(RelyingPartyRegistrationResolver.class);
		given(relyingParties.resolve(any(), any())).willReturn(this.registration);
		Converter<HttpServletRequest, String> relayState = mock(Converter.class);
		given(relayState.convert(any())).willReturn("state");
		OpenSaml4AuthenticationRequestResolver resolver = new OpenSaml4AuthenticationRequestResolver(relyingParties);
		resolver.setRelayStateResolver(relayState);
		Saml2RedirectAuthenticationRequest authnRequest = resolver.resolve(this.request);
		assertThat(authnRequest.getRelayState()).isEqualTo("state");
		verify(relayState).convert(any());
	}

	@Test
	void resolveWhenCustomAuthenticationUrlTHenUses() {
		RelyingPartyRegistrationResolver relyingParties = mock(RelyingPartyRegistrationResolver.class);
		given(relyingParties.resolve(any(), any())).willReturn(this.registration);
		OpenSaml4AuthenticationRequestResolver resolver = new OpenSaml4AuthenticationRequestResolver(relyingParties);
		resolver.setRequestMatcher(new AntPathRequestMatcher("/custom/authentication/{registrationId}"));
		Saml2RedirectAuthenticationRequest authnRequest = resolver
				.resolve(givenRequest("/custom/authentication/registration-id"));

		assertThat(authnRequest.getBinding()).isEqualTo(Saml2MessageBinding.REDIRECT);
		assertThat(authnRequest.getAuthenticationRequestUri())
				.isEqualTo(this.registration.getAssertingPartyDetails().getSingleSignOnServiceLocation());

	}

	private MockHttpServletRequest givenRequest(String path) {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath(path);
		return request;
	}

}
