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

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.mock;

/**
 * Tests for {@link OpenSamlLogoutRequestResolver}
 *
 * @author Josh Cummings
 */
public class OpenSamlLogoutRequestResolverTests {

	private final RelyingPartyRegistrationResolver resolver = mock(RelyingPartyRegistrationResolver.class);

	private final OpenSamlLogoutRequestResolver logoutResolver = new OpenSamlLogoutRequestResolver(this.resolver);

	@Test
	public void resolveRedirectWhenAuthenticatedThenIncludesName() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		Saml2Authentication authentication = authentication(registration);
		HttpServletRequest request = new MockHttpServletRequest();
		given(this.resolver.resolve(request, registration.getRegistrationId())).willReturn(registration);
		Saml2LogoutRequest saml2LogoutRequest = this.logoutResolver.resolveLogoutRequest(request, authentication)
				.logoutRequest();
		assertThat(saml2LogoutRequest.getParameter("SigAlg")).isNotNull();
		assertThat(saml2LogoutRequest.getParameter("Signature")).isNotNull();
		Saml2MessageBinding binding = registration.getAssertingPartyDetails().getSingleLogoutServiceBinding();
		LogoutRequest logoutRequest = getLogoutRequest(saml2LogoutRequest.getSamlRequest(), binding);
		assertThat(logoutRequest.getNameID().getValue()).isEqualTo(authentication.getName());
	}

	@Test
	public void resolvePostWhenAuthenticatedThenIncludesName() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full()
				.assertingPartyDetails((party) -> party.singleLogoutServiceBinding(Saml2MessageBinding.POST)).build();
		Saml2Authentication authentication = authentication(registration);
		HttpServletRequest request = new MockHttpServletRequest();
		given(this.resolver.resolve(request, registration.getRegistrationId())).willReturn(registration);
		Saml2LogoutRequest saml2LogoutRequest = this.logoutResolver.resolveLogoutRequest(request, authentication)
				.logoutRequest();
		assertThat(saml2LogoutRequest.getParameter("SigAlg")).isNull();
		assertThat(saml2LogoutRequest.getParameter("Signature")).isNull();
		Saml2MessageBinding binding = registration.getAssertingPartyDetails().getSingleLogoutServiceBinding();
		LogoutRequest logoutRequest = getLogoutRequest(saml2LogoutRequest.getSamlRequest(), binding);
		assertThat(logoutRequest.getNameID().getValue()).isEqualTo(authentication.getName());
	}

	private Saml2Authentication authentication(RelyingPartyRegistration registration) {
		return new Saml2Authentication(new DefaultSaml2AuthenticatedPrincipal("user", new HashMap<>()), "response",
				new ArrayList<>(), registration.getRegistrationId());
	}

	private LogoutRequest getLogoutRequest(String samlRequest, Saml2MessageBinding binding) {
		if (binding == Saml2MessageBinding.REDIRECT) {
			samlRequest = Saml2Utils.samlInflate(Saml2Utils.samlDecode(samlRequest));
		}
		else {
			samlRequest = new String(Saml2Utils.samlDecode(samlRequest), StandardCharsets.UTF_8);
		}
		try {
			Document document = XMLObjectProviderRegistrySupport.getParserPool()
					.parse(new ByteArrayInputStream(samlRequest.getBytes(StandardCharsets.UTF_8)));
			Element element = document.getDocumentElement();
			return (LogoutRequest) XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(element)
					.unmarshall(element);
		}
		catch (Exception ex) {
			throw new Saml2Exception(ex);
		}
	}

}
