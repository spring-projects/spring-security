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

package org.springframework.security.saml2.provider.service.registration;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationRequestFactory;

import static org.assertj.core.api.Assertions.assertThat;

public class SamlMetadataParserTest {

	@Before
	public void setUp() {
		new OpenSamlAuthenticationRequestFactory(); // ensure OpenSaml is bootstraped
	}

	@Test
	public void shouldParseIdentityProviderMetadata() throws SamlMetadataParsingException {
		// given

		SamlMetadataParser samlMetadataParser = new SamlMetadataParser("{baseUrl}/saml2/authenticate/{registrationId}");

		// when
		RelyingPartyRegistration registration = samlMetadataParser.parseIdentityProviderMetadata("sample", metadata);

		// then
		assertThat(registration.getRegistrationId()).isEqualTo("sample");
		assertThat(registration.getProviderDetails().getEntityId()).isEqualTo("https://idp.com/saml2/sample");
		assertThat(registration.getProviderDetails().getWebSsoUrl()).isEqualTo("https://idp.com/saml2/redirect/sample");
		assertThat(registration.getProviderDetails().getBinding()).isEqualTo(Saml2MessageBinding.REDIRECT);
		assertThat(registration.getProviderDetails().isSignAuthNRequest()).isEqualTo(false);
		assertThat(registration.getVerificationCredentials()).hasSize(1);
	}

	String metadata = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n" +
			"<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://idp.com/saml2/sample\">\n" +
			"  <md:IDPSSODescriptor WantAuthnRequestsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
			"    <md:KeyDescriptor use=\"signing\">\n" +
			"      <ds:KeyInfo xmlns:ds=\"" + SignatureConstants.XMLSIG_NS + "\">\n" + // needed to hack checkstyle nohttp rule
			"        <ds:X509Data>\n" +
			"          <ds:X509Certificate>MIICaDCCAdGgAwIBAgIBADANBgkqhkiG9w0BAQsFADBRMQswCQYDVQQGEwJwbDEU\n" +
			"              MBIGA1UECAwLbWF6b3dpZWNraWUxGDAWBgNVBAoMD3NwcmluZy1zZWN1cml0eTES\n" +
			"              MBAGA1UEAwwJc3ByaW5nLmlvMB4XDTIwMDcwMzIwMTY0N1oXDTIxMDcwMzIwMTY0\n" +
			"              N1owUTELMAkGA1UEBhMCcGwxFDASBgNVBAgMC21hem93aWVja2llMRgwFgYDVQQK\n" +
			"              DA9zcHJpbmctc2VjdXJpdHkxEjAQBgNVBAMMCXNwcmluZy5pbzCBnzANBgkqhkiG\n" +
			"              9w0BAQEFAAOBjQAwgYkCgYEAxKWRRGu8t00CzVY1CYICWrP0x5BL82oNWY/q5gRL\n" +
			"              zqMpFzHNiREG26RRTtaW1k71ML1aMZeUJqJaLRJnxOhy4PYDg69NUluO8kOgyquz\n" +
			"              kt5CemQpX3XTpvV7ZWnyoIejd9pQBtVG2kkxW1S5lrEBR9z5xjxsvwBjg/i5o7Hi\n" +
			"              TMsCAwEAAaNQME4wHQYDVR0OBBYEFJZjmzx7Plro+WwMlhBbuUTmmKR0MB8GA1Ud\n" +
			"              IwQYMBaAFJZjmzx7Plro+WwMlhBbuUTmmKR0MAwGA1UdEwQFMAMBAf8wDQYJKoZI\n" +
			"              hvcNAQELBQADgYEAa0OEr+TB26HvSnvQsCPWnZbvqDkubTfuANbDu8TSzdOgblmu\n" +
			"              7u4GDrs+uJ/4dxZjnjYfjSLI1W58Ib0BvRS3JKZEHfxpXhqVgSdRtljg9fv09yeA\n" +
			"              jv0eJEGd5teS78/PFw7ORnnAZ2ZrT/jz34siJrtDmZhQRsusYtSuxGJEmmk=\n" +
			"              </ds:X509Certificate>\n" +
			"        </ds:X509Data>\n" +
			"      </ds:KeyInfo>\n" +
			"    </md:KeyDescriptor>\n" +
			"    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\n" +
			"    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.com/saml2/redirect/sample\"/>\n" +
			"    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://idp.com/saml2/post/sample\"/>\n" +
			"  </md:IDPSSODescriptor>\n" +
			"</md:EntityDescriptor>";
}
