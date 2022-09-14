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

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

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

/**
 * Tests for {@link OpenSaml4LogoutRequestResolver}
 */
public class OpenSaml4LogoutRequestResolverTests {

	RelyingPartyRegistrationResolver relyingPartyRegistrationResolver = mock(RelyingPartyRegistrationResolver.class);

	@Test
	public void resolveWhenCustomParametersConsumerThenUses() {
		OpenSaml4LogoutRequestResolver logoutRequestResolver = new OpenSaml4LogoutRequestResolver(
				this.relyingPartyRegistrationResolver);
		logoutRequestResolver.setParametersConsumer((parameters) -> parameters.getLogoutRequest().setID("myid"));
		HttpServletRequest request = new MockHttpServletRequest();
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.relyingPartyRegistration()
				.assertingPartyDetails((party) -> party.singleLogoutServiceLocation("https://ap.example.com/logout"))
				.build();
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(registration);
		Saml2LogoutRequest logoutRequest = logoutRequestResolver.resolve(request, authentication);
		assertThat(logoutRequest.getId()).isEqualTo("myid");
	}

	@Test
	public void setParametersConsumerWhenNullThenIllegalArgument() {
		OpenSaml4LogoutRequestResolver logoutRequestResolver = new OpenSaml4LogoutRequestResolver(
				this.relyingPartyRegistrationResolver);
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> logoutRequestResolver.setParametersConsumer(null));
	}

}
