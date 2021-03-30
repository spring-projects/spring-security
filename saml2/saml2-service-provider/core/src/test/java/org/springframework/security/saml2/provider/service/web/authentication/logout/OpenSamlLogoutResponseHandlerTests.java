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

import org.junit.Before;
import org.junit.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.StatusCode;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.OpenSamlSigningUtils.QueryParametersPartial;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.mock;

/**
 * Tests for {@link OpenSamlLogoutResponseHandler}
 *
 * @author Josh Cummings
 */
public class OpenSamlLogoutResponseHandlerTests {

	private final RelyingPartyRegistrationResolver resolver = mock(RelyingPartyRegistrationResolver.class);

	private final Saml2LogoutRequestRepository repository = mock(Saml2LogoutRequestRepository.class);

	private final OpenSamlLogoutResponseHandler handler = new OpenSamlLogoutResponseHandler(this.resolver);

	@Before
	public void setUp() {
		this.handler.setLogoutRequestRepository(this.repository);
	}

	@Test
	public void handleWhenAuthenticatedThenHandles() {
		RelyingPartyRegistration registration = signing(verifying(registration())).build();
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration).id("id")
				.build();
		given(this.repository.removeLogoutRequest(any(), any())).willReturn(logoutRequest);
		LogoutResponse logoutResponse = TestOpenSamlObjects.assertingPartyLogoutResponse(registration);
		sign(logoutResponse, registration);
		Authentication authentication = authentication(registration);
		MockHttpServletRequest request = post(logoutResponse);
		given(this.resolver.resolve(request, registration.getRegistrationId())).willReturn(registration);
		this.handler.logout(request, null, authentication);
	}

	@Test
	public void handleWhenRedirectBindingThenValidatesSignatureParameter() {
		RelyingPartyRegistration registration = signing(verifying(registration())).build();
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration).id("id")
				.build();
		given(this.repository.removeLogoutRequest(any(), any())).willReturn(logoutRequest);
		LogoutResponse logoutResponse = TestOpenSamlObjects.assertingPartyLogoutResponse(registration);
		Authentication authentication = authentication(registration);
		MockHttpServletRequest request = redirect(logoutResponse, OpenSamlSigningUtils.sign(registration));
		given(this.resolver.resolve(request, registration.getRegistrationId())).willReturn(registration);
		this.handler.logout(request, null, authentication);
	}

	@Test
	public void handleWhenInvalidIssuerThenInvalidSignatureError() {
		RelyingPartyRegistration registration = registration().build();
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration).id("id")
				.build();
		given(this.repository.removeLogoutRequest(any(), any())).willReturn(logoutRequest);
		LogoutResponse logoutResponse = TestOpenSamlObjects.assertingPartyLogoutResponse(registration);
		logoutResponse.getIssuer().setValue("wrong");
		sign(logoutResponse, registration);
		Authentication authentication = authentication(registration);
		MockHttpServletRequest request = post(logoutResponse);
		given(this.resolver.resolve(request, registration.getRegistrationId())).willReturn(registration);
		assertThatExceptionOfType(Saml2Exception.class)
				.isThrownBy(() -> this.handler.logout(request, null, authentication))
				.withMessageContaining(Saml2ErrorCodes.INVALID_SIGNATURE);
	}

	@Test
	public void handleWhenMismatchedDestinationThenInvalidDestinationError() {
		RelyingPartyRegistration registration = registration().build();
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration).id("id")
				.build();
		given(this.repository.removeLogoutRequest(any(), any())).willReturn(logoutRequest);
		LogoutResponse logoutResponse = TestOpenSamlObjects.assertingPartyLogoutResponse(registration);
		logoutResponse.setDestination("wrong");
		sign(logoutResponse, registration);
		Authentication authentication = authentication(registration);
		MockHttpServletRequest request = post(logoutResponse);
		given(this.resolver.resolve(request, registration.getRegistrationId())).willReturn(registration);
		assertThatExceptionOfType(Saml2Exception.class)
				.isThrownBy(() -> this.handler.logout(request, null, authentication))
				.withMessageContaining(Saml2ErrorCodes.INVALID_DESTINATION);
	}

	@Test
	public void handleWhenStatusNotSuccessThenInvalidResponseError() {
		RelyingPartyRegistration registration = registration().build();
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration).id("id")
				.build();
		given(this.repository.removeLogoutRequest(any(), any())).willReturn(logoutRequest);
		LogoutResponse logoutResponse = TestOpenSamlObjects.assertingPartyLogoutResponse(registration);
		logoutResponse.getStatus().getStatusCode().setValue(StatusCode.UNKNOWN_PRINCIPAL);
		sign(logoutResponse, registration);
		Authentication authentication = authentication(registration);
		MockHttpServletRequest request = post(logoutResponse);
		given(this.resolver.resolve(request, registration.getRegistrationId())).willReturn(registration);
		assertThatExceptionOfType(Saml2Exception.class)
				.isThrownBy(() -> this.handler.logout(request, null, authentication))
				.withMessageContaining(Saml2ErrorCodes.INVALID_RESPONSE);
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

	private MockHttpServletRequest post(LogoutResponse logoutResponse) {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("POST");
		request.setParameter("SAMLResponse",
				Saml2Utils.samlEncode(serialize(logoutResponse).getBytes(StandardCharsets.UTF_8)));
		return request;
	}

	private MockHttpServletRequest redirect(LogoutResponse logoutResponse, QueryParametersPartial partial) {
		String serialized = Saml2Utils.samlEncode(Saml2Utils.samlDeflate(serialize(logoutResponse)));
		Map<String, String> parameters = partial.param("SAMLResponse", serialized).parameters();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameters(parameters);
		request.setMethod("GET");
		return request;
	}

	private void sign(LogoutResponse logoutResponse, RelyingPartyRegistration registration) {
		TestOpenSamlObjects.signed(logoutResponse, registration.getSigningX509Credentials().iterator().next(),
				registration.getAssertingPartyDetails().getEntityId());
	}

	private String serialize(XMLObject object) {
		return OpenSamlSigningUtils.serialize(object);
	}

}
