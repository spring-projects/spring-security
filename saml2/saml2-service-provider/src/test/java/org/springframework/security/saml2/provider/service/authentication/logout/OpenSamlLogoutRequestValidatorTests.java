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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.LogoutRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlSigningUtils.QueryParametersPartial;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OpenSamlLogoutRequestValidator}
 *
 * @author Josh Cummings
 */
public class OpenSamlLogoutRequestValidatorTests {

	private final OpenSamlLogoutRequestValidator manager = new OpenSamlLogoutRequestValidator();

	@Test
	public void handleWhenPostBindingThenValidates() {
		RelyingPartyRegistration registration = registration().build();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		sign(logoutRequest, registration);
		Saml2LogoutRequest request = post(logoutRequest, registration);
		Saml2LogoutRequestValidatorParameters parameters = new Saml2LogoutRequestValidatorParameters(request,
				registration, authentication(registration));
		Saml2LogoutValidatorResult result = this.manager.validate(parameters);
		assertThat(result.hasErrors()).isFalse();
	}

	@Test
	public void handleWhenNameIdIsEncryptedIdPostThenValidates() {

		RelyingPartyRegistration registration = decrypting(encrypting(registration())).build();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequestNameIdInEncryptedId(registration);
		sign(logoutRequest, registration);
		Saml2LogoutRequest request = post(logoutRequest, registration);
		Saml2LogoutRequestValidatorParameters parameters = new Saml2LogoutRequestValidatorParameters(request,
				registration, authentication(registration));
		Saml2LogoutValidatorResult result = this.manager.validate(parameters);
		assertThat(result.hasErrors()).withFailMessage(() -> result.getErrors().toString()).isFalse();

	}

	@Test
	public void handleWhenRedirectBindingThenValidatesSignatureParameter() {
		RelyingPartyRegistration registration = registration()
				.assertingPartyDetails((party) -> party.singleLogoutServiceBinding(Saml2MessageBinding.REDIRECT))
				.build();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		Saml2LogoutRequest request = redirect(logoutRequest, registration, OpenSamlSigningUtils.sign(registration));
		Saml2LogoutRequestValidatorParameters parameters = new Saml2LogoutRequestValidatorParameters(request,
				registration, authentication(registration));
		Saml2LogoutValidatorResult result = this.manager.validate(parameters);
		assertThat(result.hasErrors()).isFalse();
	}

	@Test
	public void handleWhenInvalidIssuerThenInvalidSignatureError() {
		RelyingPartyRegistration registration = registration().build();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		logoutRequest.getIssuer().setValue("wrong");
		sign(logoutRequest, registration);
		Saml2LogoutRequest request = post(logoutRequest, registration);
		Saml2LogoutRequestValidatorParameters parameters = new Saml2LogoutRequestValidatorParameters(request,
				registration, authentication(registration));
		Saml2LogoutValidatorResult result = this.manager.validate(parameters);
		assertThat(result.hasErrors()).isTrue();
		assertThat(result.getErrors().iterator().next().getErrorCode()).isEqualTo(Saml2ErrorCodes.INVALID_SIGNATURE);
	}

	@Test
	public void handleWhenMismatchedUserThenInvalidRequestError() {
		RelyingPartyRegistration registration = registration().build();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		logoutRequest.getNameID().setValue("wrong");
		sign(logoutRequest, registration);
		Saml2LogoutRequest request = post(logoutRequest, registration);
		Saml2LogoutRequestValidatorParameters parameters = new Saml2LogoutRequestValidatorParameters(request,
				registration, authentication(registration));
		Saml2LogoutValidatorResult result = this.manager.validate(parameters);
		assertThat(result.hasErrors()).isTrue();
		assertThat(result.getErrors().iterator().next().getErrorCode()).isEqualTo(Saml2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void handleWhenMissingUserThenSubjectNotFoundError() {
		RelyingPartyRegistration registration = registration().build();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		logoutRequest.setNameID(null);
		sign(logoutRequest, registration);
		Saml2LogoutRequest request = post(logoutRequest, registration);
		Saml2LogoutRequestValidatorParameters parameters = new Saml2LogoutRequestValidatorParameters(request,
				registration, authentication(registration));
		Saml2LogoutValidatorResult result = this.manager.validate(parameters);
		assertThat(result.hasErrors()).isTrue();
		assertThat(result.getErrors().iterator().next().getErrorCode()).isEqualTo(Saml2ErrorCodes.SUBJECT_NOT_FOUND);
	}

	@Test
	public void handleWhenMismatchedDestinationThenInvalidDestinationError() {
		RelyingPartyRegistration registration = registration().build();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		logoutRequest.setDestination("wrong");
		sign(logoutRequest, registration);
		Saml2LogoutRequest request = post(logoutRequest, registration);
		Saml2LogoutRequestValidatorParameters parameters = new Saml2LogoutRequestValidatorParameters(request,
				registration, authentication(registration));
		Saml2LogoutValidatorResult result = this.manager.validate(parameters);
		assertThat(result.hasErrors()).isTrue();
		assertThat(result.getErrors().iterator().next().getErrorCode()).isEqualTo(Saml2ErrorCodes.INVALID_DESTINATION);
	}

	// gh-10923
	@Test
	public void handleWhenLogoutResponseHasLineBreaksThenHandles() {
		RelyingPartyRegistration registration = registration().build();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		sign(logoutRequest, registration);
		String encoded = new StringBuffer(
				Saml2Utils.samlEncode(serialize(logoutRequest).getBytes(StandardCharsets.UTF_8))).insert(10, "\r\n")
						.toString();
		Saml2LogoutRequest request = Saml2LogoutRequest.withRelyingPartyRegistration(registration).samlRequest(encoded)
				.build();
		Saml2LogoutRequestValidatorParameters parameters = new Saml2LogoutRequestValidatorParameters(request,
				registration, authentication(registration));
		Saml2LogoutValidatorResult result = this.manager.validate(parameters);
		assertThat(result.hasErrors()).isFalse();
	}

	private RelyingPartyRegistration.Builder registration() {
		return signing(verifying(TestRelyingPartyRegistrations.noCredentials()))
				.assertingPartyDetails((party) -> party.singleLogoutServiceBinding(Saml2MessageBinding.POST));
	}

	private RelyingPartyRegistration.Builder decrypting(RelyingPartyRegistration.Builder builder) {
		return builder
				.decryptionX509Credentials((c) -> c.add(TestSaml2X509Credentials.relyingPartyDecryptingCredential()));
	}

	private RelyingPartyRegistration.Builder encrypting(RelyingPartyRegistration.Builder builder) {
		return builder.assertingPartyDetails((party) -> party.encryptionX509Credentials(
				(c) -> c.add(TestSaml2X509Credentials.assertingPartyEncryptingCredential())));
	}

	private RelyingPartyRegistration.Builder verifying(RelyingPartyRegistration.Builder builder) {
		return builder.assertingPartyDetails((party) -> party
				.verificationX509Credentials((c) -> c.add(TestSaml2X509Credentials.relyingPartyVerifyingCredential())));
	}

	private RelyingPartyRegistration.Builder signing(RelyingPartyRegistration.Builder builder) {
		return builder.signingX509Credentials((c) -> c.add(TestSaml2X509Credentials.assertingPartySigningCredential()));
	}

	private Authentication authentication(RelyingPartyRegistration registration) {
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("user", new HashMap<>());
		principal.setRelyingPartyRegistrationId(registration.getRegistrationId());
		return new Saml2Authentication(principal, "response", new ArrayList<>());
	}

	private Saml2LogoutRequest post(LogoutRequest logoutRequest, RelyingPartyRegistration registration) {
		return Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest(Saml2Utils.samlEncode(serialize(logoutRequest).getBytes(StandardCharsets.UTF_8))).build();
	}

	private Saml2LogoutRequest redirect(LogoutRequest logoutRequest, RelyingPartyRegistration registration,
			QueryParametersPartial partial) {
		String serialized = Saml2Utils.samlEncode(Saml2Utils.samlDeflate(serialize(logoutRequest)));
		Map<String, String> parameters = partial.param(Saml2ParameterNames.SAML_REQUEST, serialized).parameters();
		return Saml2LogoutRequest.withRelyingPartyRegistration(registration).samlRequest(serialized)
				.parameters((params) -> params.putAll(parameters)).build();
	}

	private void sign(LogoutRequest logoutRequest, RelyingPartyRegistration registration) {
		TestOpenSamlObjects.signed(logoutRequest, registration.getSigningX509Credentials().iterator().next(),
				registration.getAssertingPartyDetails().getEntityId());
	}

	private String serialize(XMLObject object) {
		return OpenSamlSigningUtils.serialize(object);
	}

}
