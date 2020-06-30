/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.saml2.provider.service.servlet.filter;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

import javax.servlet.http.HttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding.REDIRECT;

public class SamlMetadataGeneratorTest {

	@Before
	public void setUp() {
		new OpenSamlAuthenticationRequestFactory(); // ensure OpenSaml is bootstraped
	}

	@Test
	public void shouldGenerateMetadata() {
		// given
		SamlMetadataGenerator samlMetadataGenerator = new SamlMetadataGenerator();
		RelyingPartyRegistration relyingPartyRegistration = TestRelyingPartyRegistrations.relyingPartyRegistration()
				.providerDetails(p -> p.binding(REDIRECT))
				.providerDetails(p -> p.signAuthNRequest(true))
				.build();
		HttpServletRequest servletRequestMock = new MockHttpServletRequest();

		// when
		String metadataXml = samlMetadataGenerator.generateMetadata(relyingPartyRegistration, servletRequestMock);

		// then
		assertThat(metadataXml)
				.contains("<EntityDescriptor")
				.contains("entityID=\"http://localhost/saml2/service-provider-metadata/simplesamlphp\"")
				.contains("AuthnRequestsSigned=\"true\"")
				.contains("WantAssertionsSigned=\"true\"")
				.contains("<md:KeyDescriptor use=\"signing\">")
				.contains("<ds:X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBh")
				.contains("<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>")
				.contains("Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"")
				.contains("Location=\"http://localhost/login/saml2/sso/simplesamlphp\" index=\"1\"");
	}

}
