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

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;

import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.StatusCode;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link OpenSamlLogoutResponseResolver}
 *
 * @author Josh Cummings
 */
public class OpenSamlLogoutResponseResolverTests {

	RelyingPartyRegistrationResolver relyingPartyRegistrationResolver = mock(RelyingPartyRegistrationResolver.class);

	OpenSamlLogoutResponseResolver logoutResponseResolver = new OpenSamlLogoutResponseResolver(
			this.relyingPartyRegistrationResolver);

	@Test
	public void resolveRedirectWhenAuthenticatedThenSuccess() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		MockHttpServletRequest request = new MockHttpServletRequest();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		request.setParameter(Saml2ParameterNames.SAML_REQUEST,
				Saml2Utils.samlEncode(OpenSamlSigningUtils.serialize(logoutRequest).getBytes()));
		request.setParameter(Saml2ParameterNames.RELAY_STATE, "abcd");
		Authentication authentication = authentication(registration);
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(registration);
		Saml2LogoutResponse saml2LogoutResponse = this.logoutResponseResolver.resolve(request, authentication);
		assertThat(saml2LogoutResponse.getParameter(Saml2ParameterNames.SIG_ALG)).isNotNull();
		assertThat(saml2LogoutResponse.getParameter(Saml2ParameterNames.SIGNATURE)).isNotNull();
		assertThat(saml2LogoutResponse.getParameter(Saml2ParameterNames.RELAY_STATE)).isSameAs("abcd");
		Saml2MessageBinding binding = registration.getAssertingPartyDetails().getSingleLogoutServiceBinding();
		LogoutResponse logoutResponse = getLogoutResponse(saml2LogoutResponse.getSamlResponse(), binding);
		assertThat(logoutResponse.getStatus().getStatusCode().getValue()).isEqualTo(StatusCode.SUCCESS);
	}

	@Test
	public void resolvePostWhenAuthenticatedThenSuccess() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full()
				.assertingPartyDetails((party) -> party.singleLogoutServiceBinding(Saml2MessageBinding.POST)).build();
		MockHttpServletRequest request = new MockHttpServletRequest();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		request.setParameter(Saml2ParameterNames.SAML_REQUEST,
				Saml2Utils.samlEncode(OpenSamlSigningUtils.serialize(logoutRequest).getBytes()));
		request.setParameter(Saml2ParameterNames.RELAY_STATE, "abcd");
		Authentication authentication = authentication(registration);
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(registration);
		Saml2LogoutResponse saml2LogoutResponse = this.logoutResponseResolver.resolve(request, authentication);
		assertThat(saml2LogoutResponse.getParameter(Saml2ParameterNames.SIG_ALG)).isNull();
		assertThat(saml2LogoutResponse.getParameter(Saml2ParameterNames.SIGNATURE)).isNull();
		assertThat(saml2LogoutResponse.getParameter(Saml2ParameterNames.RELAY_STATE)).isSameAs("abcd");
		Saml2MessageBinding binding = registration.getAssertingPartyDetails().getSingleLogoutServiceBinding();
		LogoutResponse logoutResponse = getLogoutResponse(saml2LogoutResponse.getSamlResponse(), binding);
		assertThat(logoutResponse.getStatus().getStatusCode().getValue()).isEqualTo(StatusCode.SUCCESS);
	}

	// gh-10923
	@Test
	public void resolvePostWithLineBreaksWhenAuthenticatedThenSuccess() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full()
				.assertingPartyDetails((party) -> party.singleLogoutServiceBinding(Saml2MessageBinding.POST)).build();
		MockHttpServletRequest request = new MockHttpServletRequest();
		LogoutRequest logoutRequest = TestOpenSamlObjects.assertingPartyLogoutRequest(registration);
		String encoded = new StringBuffer(
				Saml2Utils.samlEncode(OpenSamlSigningUtils.serialize(logoutRequest).getBytes())).insert(10, "\r\n")
						.toString();
		request.setParameter(Saml2ParameterNames.SAML_REQUEST, encoded);
		request.setParameter(Saml2ParameterNames.RELAY_STATE, "abcd");
		Authentication authentication = authentication(registration);
		given(this.relyingPartyRegistrationResolver.resolve(any(), any())).willReturn(registration);
		Saml2LogoutResponse saml2LogoutResponse = this.logoutResponseResolver.resolve(request, authentication);
		assertThat(saml2LogoutResponse.getParameter(Saml2ParameterNames.SIG_ALG)).isNull();
		assertThat(saml2LogoutResponse.getParameter(Saml2ParameterNames.SIGNATURE)).isNull();
		assertThat(saml2LogoutResponse.getParameter(Saml2ParameterNames.RELAY_STATE)).isSameAs("abcd");
		Saml2MessageBinding binding = registration.getAssertingPartyDetails().getSingleLogoutServiceBinding();
		LogoutResponse logoutResponse = getLogoutResponse(saml2LogoutResponse.getSamlResponse(), binding);
		assertThat(logoutResponse.getStatus().getStatusCode().getValue()).isEqualTo(StatusCode.SUCCESS);
	}

	private Saml2Authentication authentication(RelyingPartyRegistration registration) {
		DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal("user", new HashMap<>());
		principal.setRelyingPartyRegistrationId(registration.getRegistrationId());
		return new Saml2Authentication(principal, "response", new ArrayList<>());
	}

	private LogoutResponse getLogoutResponse(String saml2Response, Saml2MessageBinding binding) {
		if (binding == Saml2MessageBinding.REDIRECT) {
			saml2Response = Saml2Utils.samlInflate(Saml2Utils.samlDecode(saml2Response));
		}
		else {
			saml2Response = new String(Saml2Utils.samlDecode(saml2Response), StandardCharsets.UTF_8);
		}
		try {
			Document document = XMLObjectProviderRegistrySupport.getParserPool()
					.parse(new ByteArrayInputStream(saml2Response.getBytes(StandardCharsets.UTF_8)));
			Element element = document.getDocumentElement();
			return (LogoutResponse) XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(element)
					.unmarshall(element);
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
	}

}
