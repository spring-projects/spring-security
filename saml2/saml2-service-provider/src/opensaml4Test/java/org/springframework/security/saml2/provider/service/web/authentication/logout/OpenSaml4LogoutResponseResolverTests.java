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

import java.util.function.Consumer;

import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.LogoutRequest;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSaml4LogoutResponseResolver.LogoutResponseParameters;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link OpenSaml4LogoutResponseResolver}
 */
public class OpenSaml4LogoutResponseResolverTests {

	RelyingPartyRegistrationResolver relyingPartyRegistrationResolver = mock(RelyingPartyRegistrationResolver.class);

	@Test
	public void resolveWhenCustomParametersConsumerThenUses() {
		OpenSaml4LogoutResponseResolver logoutResponseResolver = new OpenSaml4LogoutResponseResolver(
				this.relyingPartyRegistrationResolver);
		Consumer<LogoutResponseParameters> parametersConsumer = mock(Consumer.class);
		logoutResponseResolver.setParametersConsumer(parametersConsumer);
		MockHttpServletRequest request = new MockHttpServletRequest();
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.relyingPartyRegistration()
				.assertingPartyDetails(
						(party) -> party.singleLogoutServiceResponseLocation("https://ap.example.com/logout"))
				.build();
		Authentication authentication = new TestingAuthenticationToken("user", "password");
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		request.setParameter(Saml2ParameterNames.SAML_REQUEST,
				Saml2Utils.samlEncode(OpenSamlSigningUtils.serialize(logoutRequest).getBytes()));
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(registration);
		Saml2LogoutResponse logoutResponse = logoutResponseResolver.resolve(request, authentication);
		assertThat(logoutResponse).isNotNull();
		verify(parametersConsumer).accept(any());
	}

	@Test
	public void setParametersConsumerWhenNullThenIllegalArgument() {
		OpenSaml4LogoutRequestResolver logoutRequestResolver = new OpenSaml4LogoutRequestResolver(
				this.relyingPartyRegistrationResolver);
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> logoutRequestResolver.setParametersConsumer(null));
	}

}
