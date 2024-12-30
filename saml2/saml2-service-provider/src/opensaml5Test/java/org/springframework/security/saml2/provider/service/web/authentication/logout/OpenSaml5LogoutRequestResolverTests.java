/*
 * Copyright 2002-2023 the original author or authors.
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

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OpenSaml5LogoutRequestResolver}
 */
public class OpenSaml5LogoutRequestResolverTests {

	RelyingPartyRegistration registration;

	RelyingPartyRegistrationResolver registrationResolver;

	OpenSaml5LogoutRequestResolver logoutRequestResolver;

	@BeforeEach
	public void setup() {
		this.registration = TestRelyingPartyRegistrations.full().build();
		this.registrationResolver = mock(RelyingPartyRegistrationResolver.class);
		this.logoutRequestResolver = new OpenSaml5LogoutRequestResolver(this.registrationResolver);
	}

	@Test
	public void resolveWhenCustomParametersConsumerThenUses() {
		this.logoutRequestResolver.setParametersConsumer((parameters) -> parameters.getLogoutRequest().setID("myid"));
		given(this.registrationResolver.resolve(any(), any())).willReturn(this.registration);

		Saml2LogoutRequest logoutRequest = this.logoutRequestResolver.resolve(givenRequest(), givenAuthentication());

		assertThat(logoutRequest.getId()).isEqualTo("myid");
	}

	@Test
	public void setParametersConsumerWhenNullThenIllegalArgument() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> this.logoutRequestResolver.setParametersConsumer(null));
	}

	@Test
	public void resolveWhenCustomRelayStateThenUses() {
		given(this.registrationResolver.resolve(any(), any())).willReturn(this.registration);
		Converter<HttpServletRequest, String> relayState = mock(Converter.class);
		given(relayState.convert(any())).willReturn("any-state");
		this.logoutRequestResolver.setRelayStateResolver(relayState);

		Saml2LogoutRequest logoutRequest = this.logoutRequestResolver.resolve(givenRequest(), givenAuthentication());

		assertThat(logoutRequest.getRelayState()).isEqualTo("any-state");
		verify(relayState).convert(any());
	}

	private static Authentication givenAuthentication() {
		return new TestingAuthenticationToken("user", "password");
	}

	private MockHttpServletRequest givenRequest() {
		return new MockHttpServletRequest();
	}

}
