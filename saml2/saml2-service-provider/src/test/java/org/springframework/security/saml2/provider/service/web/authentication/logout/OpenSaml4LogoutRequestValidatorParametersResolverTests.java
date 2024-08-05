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

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.opensaml.core.xml.XMLObject;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects;
import org.springframework.security.saml2.provider.service.authentication.TestSaml2Authentications;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequestValidatorParameters;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
public final class OpenSaml4LogoutRequestValidatorParametersResolverTests {

	@Mock
	RelyingPartyRegistrationRepository registrations;

	private final OpenSamlOperations saml = new OpenSaml4Template();

	private RelyingPartyRegistration registration = TestRelyingPartyRegistrations.relyingPartyRegistration().build();

	private OpenSaml4LogoutRequestValidatorParametersResolver resolver;

	@BeforeEach
	void setup() {
		this.resolver = new OpenSaml4LogoutRequestValidatorParametersResolver(this.registrations);
	}

	@Test
	void saml2LogoutRegistrationIdResolveWhenMatchesThenParameters() {
		String registrationId = this.registration.getRegistrationId();
		MockHttpServletRequest request = post("/logout/saml2/slo/" + registrationId);
		Authentication authentication = new TestingAuthenticationToken("user", "pass");
		request.setParameter(Saml2ParameterNames.SAML_REQUEST, "request");
		given(this.registrations.findByRegistrationId(registrationId)).willReturn(this.registration);
		Saml2LogoutRequestValidatorParameters parameters = this.resolver.resolve(request, authentication);
		assertThat(parameters.getAuthentication()).isEqualTo(authentication);
		assertThat(parameters.getRelyingPartyRegistration().getRegistrationId()).isEqualTo(registrationId);
		assertThat(parameters.getLogoutRequest().getSamlRequest()).isEqualTo("request");
	}

	@Test
	void saml2LogoutRegistrationIdWhenUnauthenticatedThenParameters() {
		String registrationId = this.registration.getRegistrationId();
		MockHttpServletRequest request = post("/logout/saml2/slo/" + registrationId);
		request.setParameter(Saml2ParameterNames.SAML_REQUEST, "request");
		given(this.registrations.findByRegistrationId(registrationId)).willReturn(this.registration);
		Saml2LogoutRequestValidatorParameters parameters = this.resolver.resolve(request, null);
		assertThat(parameters.getAuthentication()).isNull();
		assertThat(parameters.getRelyingPartyRegistration().getRegistrationId()).isEqualTo(registrationId);
		assertThat(parameters.getLogoutRequest().getSamlRequest()).isEqualTo("request");
	}

	@Test
	void saml2LogoutResolveWhenAuthenticatedThenParameters() {
		String registrationId = this.registration.getRegistrationId();
		MockHttpServletRequest request = post("/logout/saml2/slo");
		Authentication authentication = TestSaml2Authentications.authentication();
		request.setParameter(Saml2ParameterNames.SAML_REQUEST, "request");
		given(this.registrations.findByRegistrationId(registrationId)).willReturn(this.registration);
		Saml2LogoutRequestValidatorParameters parameters = this.resolver.resolve(request, authentication);
		assertThat(parameters.getAuthentication()).isEqualTo(authentication);
		assertThat(parameters.getRelyingPartyRegistration().getRegistrationId()).isEqualTo(registrationId);
		assertThat(parameters.getLogoutRequest().getSamlRequest()).isEqualTo("request");
	}

	@Test
	void saml2LogoutResolveWhenUnauthenticatedThenParameters() {
		String registrationId = this.registration.getRegistrationId();
		MockHttpServletRequest request = post("/logout/saml2/slo");
		String logoutRequest = serialize(TestOpenSamlObjects.logoutRequest());
		String encoded = Saml2Utils.samlEncode(logoutRequest.getBytes(StandardCharsets.UTF_8));
		request.setParameter(Saml2ParameterNames.SAML_REQUEST, encoded);
		given(this.registrations.findUniqueByAssertingPartyEntityId(TestOpenSamlObjects.ASSERTING_PARTY_ENTITY_ID))
			.willReturn(this.registration);
		Saml2LogoutRequestValidatorParameters parameters = this.resolver.resolve(request, null);
		assertThat(parameters.getAuthentication()).isNull();
		assertThat(parameters.getRelyingPartyRegistration().getRegistrationId()).isEqualTo(registrationId);
		assertThat(parameters.getLogoutRequest().getSamlRequest()).isEqualTo(encoded);
	}

	@Test
	void saml2LogoutResolveWhenUnauthenticatedGetRequestThenInflates() {
		String registrationId = this.registration.getRegistrationId();
		MockHttpServletRequest request = get("/logout/saml2/slo");
		String logoutRequest = serialize(TestOpenSamlObjects.logoutRequest());
		String encoded = Saml2Utils.samlEncode(Saml2Utils.samlDeflate(logoutRequest));
		request.setParameter(Saml2ParameterNames.SAML_REQUEST, encoded);
		given(this.registrations.findUniqueByAssertingPartyEntityId(TestOpenSamlObjects.ASSERTING_PARTY_ENTITY_ID))
			.willReturn(this.registration);
		Saml2LogoutRequestValidatorParameters parameters = this.resolver.resolve(request, null);
		assertThat(parameters.getAuthentication()).isNull();
		assertThat(parameters.getRelyingPartyRegistration().getRegistrationId()).isEqualTo(registrationId);
		assertThat(parameters.getLogoutRequest().getSamlRequest()).isEqualTo(encoded);
	}

	@Test
	void saml2LogoutRegistrationIdResolveWhenNoMatchingRegistrationIdThenSaml2Exception() {
		MockHttpServletRequest request = post("/logout/saml2/slo/id");
		request.setParameter(Saml2ParameterNames.SAML_REQUEST, "request");
		assertThatExceptionOfType(Saml2AuthenticationException.class)
			.isThrownBy(() -> this.resolver.resolve(request, null));
	}

	private MockHttpServletRequest post(String uri) {
		MockHttpServletRequest request = new MockHttpServletRequest("POST", uri);
		request.setServletPath(uri);
		return request;
	}

	private MockHttpServletRequest get(String uri) {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", uri);
		request.setServletPath(uri);
		return request;
	}

	private String serialize(XMLObject object) {
		return this.saml.serialize(object).serialize();
	}

}
