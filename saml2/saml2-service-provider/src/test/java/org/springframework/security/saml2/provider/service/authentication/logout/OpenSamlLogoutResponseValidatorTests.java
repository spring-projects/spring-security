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

package org.springframework.security.saml2.provider.service.authentication.logout;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.StatusCode;

import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlSigningUtils.QueryParametersPartial;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OpenSamlLogoutResponseValidator}
 *
 * @author Josh Cummings
 */
public class OpenSamlLogoutResponseValidatorTests {

	private final OpenSamlLogoutResponseValidator manager = new OpenSamlLogoutResponseValidator();

	@Test
	public void handleWhenAuthenticatedThenHandles() {
		RelyingPartyRegistration registration = signing(verifying(registration())).build();
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration).id("id")
				.build();
		LogoutResponse logoutResponse = TestOpenSamlObjects.assertingPartyLogoutResponse(registration);
		sign(logoutResponse, registration);
		Saml2LogoutResponse response = post(logoutResponse, registration);
		Saml2LogoutResponseValidatorParameters parameters = new Saml2LogoutResponseValidatorParameters(response,
				logoutRequest, registration);
		this.manager.validate(parameters);
	}

	@Test
	public void handleWhenRedirectBindingThenValidatesSignatureParameter() {
		RelyingPartyRegistration registration = signing(verifying(registration()))
				.assertingPartyDetails((party) -> party.singleLogoutServiceBinding(Saml2MessageBinding.REDIRECT))
				.build();
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration).id("id")
				.build();
		LogoutResponse logoutResponse = TestOpenSamlObjects.assertingPartyLogoutResponse(registration);
		Saml2LogoutResponse response = redirect(logoutResponse, registration, OpenSamlSigningUtils.sign(registration));
		Saml2LogoutResponseValidatorParameters parameters = new Saml2LogoutResponseValidatorParameters(response,
				logoutRequest, registration);
		this.manager.validate(parameters);
	}

	@Test
	public void handleWhenInvalidIssuerThenInvalidSignatureError() {
		RelyingPartyRegistration registration = registration().build();
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration).id("id")
				.build();
		LogoutResponse logoutResponse = TestOpenSamlObjects.assertingPartyLogoutResponse(registration);
		logoutResponse.getIssuer().setValue("wrong");
		sign(logoutResponse, registration);
		Saml2LogoutResponse response = post(logoutResponse, registration);
		Saml2LogoutResponseValidatorParameters parameters = new Saml2LogoutResponseValidatorParameters(response,
				logoutRequest, registration);
		Saml2LogoutValidatorResult result = this.manager.validate(parameters);
		assertThat(result.hasErrors()).isTrue();
		assertThat(result.getErrors().iterator().next().getErrorCode()).isEqualTo(Saml2ErrorCodes.INVALID_SIGNATURE);
	}

	@Test
	public void handleWhenMismatchedDestinationThenInvalidDestinationError() {
		RelyingPartyRegistration registration = registration().build();
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration).id("id")
				.build();
		LogoutResponse logoutResponse = TestOpenSamlObjects.assertingPartyLogoutResponse(registration);
		logoutResponse.setDestination("wrong");
		sign(logoutResponse, registration);
		Saml2LogoutResponse response = post(logoutResponse, registration);
		Saml2LogoutResponseValidatorParameters parameters = new Saml2LogoutResponseValidatorParameters(response,
				logoutRequest, registration);
		Saml2LogoutValidatorResult result = this.manager.validate(parameters);
		assertThat(result.hasErrors()).isTrue();
		assertThat(result.getErrors().iterator().next().getErrorCode()).isEqualTo(Saml2ErrorCodes.INVALID_DESTINATION);
	}

	@Test
	public void handleWhenStatusNotSuccessThenInvalidResponseError() {
		RelyingPartyRegistration registration = registration().build();
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration).id("id")
				.build();
		LogoutResponse logoutResponse = TestOpenSamlObjects.assertingPartyLogoutResponse(registration);
		logoutResponse.getStatus().getStatusCode().setValue(StatusCode.UNKNOWN_PRINCIPAL);
		sign(logoutResponse, registration);
		Saml2LogoutResponse response = post(logoutResponse, registration);
		Saml2LogoutResponseValidatorParameters parameters = new Saml2LogoutResponseValidatorParameters(response,
				logoutRequest, registration);
		Saml2LogoutValidatorResult result = this.manager.validate(parameters);
		assertThat(result.hasErrors()).isTrue();
		assertThat(result.getErrors().iterator().next().getErrorCode()).isEqualTo(Saml2ErrorCodes.INVALID_RESPONSE);
	}

	// gh-10923
	@Test
	public void handleWhenLogoutResponseHasLineBreaksThenHandles() {
		RelyingPartyRegistration registration = signing(verifying(registration())).build();
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration).id("id")
				.build();
		LogoutResponse logoutResponse = TestOpenSamlObjects.assertingPartyLogoutResponse(registration);
		sign(logoutResponse, registration);
		String encoded = new StringBuilder(
				Saml2Utils.samlEncode(serialize(logoutResponse).getBytes(StandardCharsets.UTF_8))).insert(10, "\r\n")
						.toString();
		Saml2LogoutResponse response = Saml2LogoutResponse.withRelyingPartyRegistration(registration)
				.samlResponse(encoded).build();
		Saml2LogoutResponseValidatorParameters parameters = new Saml2LogoutResponseValidatorParameters(response,
				logoutRequest, registration);
		this.manager.validate(parameters);
	}

	private RelyingPartyRegistration.Builder registration() {
		return signing(verifying(TestRelyingPartyRegistrations.noCredentials()))
				.assertingPartyDetails((party) -> party.singleLogoutServiceBinding(Saml2MessageBinding.POST));
	}

	private RelyingPartyRegistration.Builder verifying(RelyingPartyRegistration.Builder builder) {
		return builder.assertingPartyDetails((party) -> party
				.verificationX509Credentials((c) -> c.add(TestSaml2X509Credentials.relyingPartyVerifyingCredential())));
	}

	private RelyingPartyRegistration.Builder signing(RelyingPartyRegistration.Builder builder) {
		return builder.signingX509Credentials((c) -> c.add(TestSaml2X509Credentials.assertingPartySigningCredential()));
	}

	private Saml2LogoutResponse post(LogoutResponse logoutResponse, RelyingPartyRegistration registration) {
		return Saml2LogoutResponse.withRelyingPartyRegistration(registration)
				.samlResponse(Saml2Utils.samlEncode(serialize(logoutResponse).getBytes(StandardCharsets.UTF_8)))
				.build();
	}

	private Saml2LogoutResponse redirect(LogoutResponse logoutResponse, RelyingPartyRegistration registration,
			QueryParametersPartial partial) {
		String serialized = Saml2Utils.samlEncode(Saml2Utils.samlDeflate(serialize(logoutResponse)));
		Map<String, String> parameters = partial.param(Saml2ParameterNames.SAML_RESPONSE, serialized).parameters();
		return Saml2LogoutResponse.withRelyingPartyRegistration(registration).samlResponse(serialized)
				.parameters((params) -> params.putAll(parameters)).build();
	}

	private void sign(LogoutResponse logoutResponse, RelyingPartyRegistration registration) {
		TestOpenSamlObjects.signed(logoutResponse, registration.getSigningX509Credentials().iterator().next(),
				registration.getAssertingPartyDetails().getEntityId());
	}

	private String serialize(XMLObject object) {
		return OpenSamlSigningUtils.serialize(object);
	}

}
