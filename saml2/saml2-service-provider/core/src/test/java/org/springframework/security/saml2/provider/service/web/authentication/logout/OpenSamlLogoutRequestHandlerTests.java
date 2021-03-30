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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.LogoutRequest;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSamlSigningUtils.QueryParametersPartial;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.mock;

/**
 * Tests for {@link OpenSamlLogoutRequestHandler}
 *
 * @author Josh Cummings
 */
public class OpenSamlLogoutRequestHandlerTests {

	private final RelyingPartyRegistrationResolver resolver = mock(RelyingPartyRegistrationResolver.class);

	private final OpenSamlLogoutRequestHandler handler = new OpenSamlLogoutRequestHandler(this.resolver);

	@Test
	public void handleWhenAuthenticatedThenSavesRequestId() {
		RelyingPartyRegistration registration = registration().build();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		sign(logoutRequest, registration);
		Authentication authentication = authentication(registration);
		MockHttpServletRequest request = post(logoutRequest);
		given(this.resolver.resolve(request, registration.getRegistrationId())).willReturn(registration);
		this.handler.logout(request, null, authentication);
		String id = ((LogoutRequest) request.getAttribute(LogoutRequest.class.getName())).getID();
		assertThat(id).isEqualTo(logoutRequest.getID());
	}

	@Test
	public void handleWhenRedirectBindingThenValidatesSignatureParameter() {
		RelyingPartyRegistration registration = registration().build();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		Authentication authentication = authentication(registration);
		MockHttpServletRequest request = redirect(logoutRequest, OpenSamlSigningUtils.sign(registration));
		given(this.resolver.resolve(request, registration.getRegistrationId())).willReturn(registration);
		this.handler.logout(request, null, authentication);
		String id = ((LogoutRequest) request.getAttribute(LogoutRequest.class.getName())).getID();
		assertThat(id).isEqualTo(logoutRequest.getID());
	}

	@Test
	public void handleWhenInvalidIssuerThenInvalidSignatureError() {
		RelyingPartyRegistration registration = registration().build();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		logoutRequest.getIssuer().setValue("wrong");
		sign(logoutRequest, registration);
		Authentication authentication = authentication(registration);
		MockHttpServletRequest request = post(logoutRequest);
		given(this.resolver.resolve(request, registration.getRegistrationId())).willReturn(registration);
		assertThatExceptionOfType(Saml2Exception.class)
				.isThrownBy(() -> this.handler.logout(request, null, authentication))
				.withMessageContaining(Saml2ErrorCodes.INVALID_SIGNATURE);
	}

	@Test
	public void handleWhenMismatchedUserThenInvalidRequestError() {
		RelyingPartyRegistration registration = registration().build();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		logoutRequest.getNameID().setValue("wrong");
		sign(logoutRequest, registration);
		Authentication authentication = authentication(registration);
		MockHttpServletRequest request = post(logoutRequest);
		given(this.resolver.resolve(request, registration.getRegistrationId())).willReturn(registration);
		assertThatExceptionOfType(Saml2Exception.class)
				.isThrownBy(() -> this.handler.logout(request, null, authentication))
				.withMessageContaining(Saml2ErrorCodes.INVALID_REQUEST);
	}

	@Test
	public void handleWhenMissingUserThenSubjectNotFoundError() {
		RelyingPartyRegistration registration = registration().build();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		logoutRequest.setNameID(null);
		sign(logoutRequest, registration);
		Authentication authentication = authentication(registration);
		MockHttpServletRequest request = post(logoutRequest);
		given(this.resolver.resolve(request, registration.getRegistrationId())).willReturn(registration);
		assertThatExceptionOfType(Saml2Exception.class)
				.isThrownBy(() -> this.handler.logout(request, null, authentication))
				.withMessageContaining(Saml2ErrorCodes.SUBJECT_NOT_FOUND);
	}

	@Test
	public void handleWhenMismatchedDestinationThenInvalidDestinationError() {
		RelyingPartyRegistration registration = registration().build();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		logoutRequest.setDestination("wrong");
		sign(logoutRequest, registration);
		Authentication authentication = authentication(registration);
		MockHttpServletRequest request = post(logoutRequest);
		given(this.resolver.resolve(request, registration.getRegistrationId())).willReturn(registration);
		assertThatExceptionOfType(Saml2Exception.class)
				.isThrownBy(() -> this.handler.logout(request, null, authentication))
				.withMessageContaining(Saml2ErrorCodes.INVALID_DESTINATION);
	}

	private RelyingPartyRegistration.Builder registration() {
		return signing(verifying(TestRelyingPartyRegistrations.noCredentials()));
	}

	private RelyingPartyRegistration.Builder verifying(RelyingPartyRegistration.Builder builder) {
		return builder.assertingPartyDetails((party) -> party
				.verificationX509Credentials((c) -> c.add(TestSaml2X509Credentials.relyingPartyVerifyingCredential())));
	}

	private RelyingPartyRegistration.Builder signing(RelyingPartyRegistration.Builder builder) {
		return builder.signingX509Credentials((c) -> c.add(TestSaml2X509Credentials.assertingPartySigningCredential()));
	}

	private Authentication authentication(RelyingPartyRegistration registration) {
		return new Saml2Authentication(new DefaultSaml2AuthenticatedPrincipal("user", new HashMap<>()), "response",
				new ArrayList<>(), registration.getRegistrationId());
	}

	private MockHttpServletRequest post(LogoutRequest logoutRequest) {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("POST");
		request.setParameter("SAMLRequest",
				Saml2Utils.samlEncode(serialize(logoutRequest).getBytes(StandardCharsets.UTF_8)));
		return request;
	}

	private MockHttpServletRequest redirect(LogoutRequest logoutRequest, QueryParametersPartial partial) {
		String serialized = Saml2Utils.samlEncode(Saml2Utils.samlDeflate(serialize(logoutRequest)));
		Map<String, String> parameters = partial.param("SAMLRequest", serialized).parameters();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameters(parameters);
		request.setMethod("GET");
		return request;
	}

	private void sign(LogoutRequest logoutRequest, RelyingPartyRegistration registration) {
		TestOpenSamlObjects.signed(logoutRequest, registration.getSigningX509Credentials().iterator().next(),
				registration.getAssertingPartyDetails().getEntityId());
	}

	private String serialize(XMLObject object) {
		return OpenSamlSigningUtils.serialize(object);
	}

}
