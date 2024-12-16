/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.saml2.provider.service.metadata;

import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OpenSamlMetadataResolver}
 */
public class OpenSamlMetadataResolverTests {

	@Test
	public void resolveWhenRelyingPartyThenMetadataMatches() {
		RelyingPartyRegistration relyingPartyRegistration = TestRelyingPartyRegistrations.full()
			.assertionConsumerServiceBinding(Saml2MessageBinding.REDIRECT)
			.build();
		OpenSamlMetadataResolver openSamlMetadataResolver = new OpenSamlMetadataResolver();
		String metadata = openSamlMetadataResolver.resolve(relyingPartyRegistration);
		assertThat(metadata).contains("<md:EntityDescriptor")
			.contains("entityID=\"rp-entity-id\"")
			.contains("<md:KeyDescriptor use=\"signing\">")
			.contains("<md:KeyDescriptor use=\"encryption\">")
			.contains("<ds:X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBh")
			.contains("Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"")
			.contains("Location=\"https://rp.example.org/acs\" index=\"1\"")
			.contains("ResponseLocation=\"https://rp.example.org/logout/saml2/response\"");
	}

	@Test
	public void resolveWhenRelyingPartyAndSignMetadataSetThenMetadataMatches() {
		RelyingPartyRegistration relyingPartyRegistration = TestRelyingPartyRegistrations.full()
			.assertionConsumerServiceBinding(Saml2MessageBinding.REDIRECT)
			.build();
		OpenSamlMetadataResolver openSamlMetadataResolver = new OpenSamlMetadataResolver();
		openSamlMetadataResolver.setSignMetadata(true);
		String metadata = openSamlMetadataResolver.resolve(relyingPartyRegistration);
		assertThat(metadata).contains("<md:EntityDescriptor")
			.contains("entityID=\"rp-entity-id\"")
			.contains("<md:KeyDescriptor use=\"signing\">")
			.contains("<md:KeyDescriptor use=\"encryption\">")
			.contains("<ds:X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBh")
			.contains("Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"")
			.contains("Location=\"https://rp.example.org/acs\" index=\"1\"")
			.contains("ResponseLocation=\"https://rp.example.org/logout/saml2/response\"")
			.contains("Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"")
			.contains("CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#")
			.contains("SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
			.contains("Reference URI=\"\"")
			.contains("Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature")
			.contains("Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"")
			.contains("DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"")
			.contains("DigestValue")
			.contains("SignatureValue");
	}

	@Test
	public void resolveWhenRelyingPartyNoCredentialsThenMetadataMatches() {
		RelyingPartyRegistration relyingPartyRegistration = TestRelyingPartyRegistrations.noCredentials()
			.assertingPartyDetails((party) -> party
				.verificationX509Credentials((c) -> c.add(TestSaml2X509Credentials.relyingPartyVerifyingCredential())))
			.build();
		OpenSamlMetadataResolver openSamlMetadataResolver = new OpenSamlMetadataResolver();
		String metadata = openSamlMetadataResolver.resolve(relyingPartyRegistration);
		assertThat(metadata).contains("<md:EntityDescriptor")
			.contains("entityID=\"rp-entity-id\"")
			.doesNotContain("<md:KeyDescriptor use=\"signing\">")
			.doesNotContain("<md:KeyDescriptor use=\"encryption\">")
			.contains("Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"")
			.contains("Location=\"https://rp.example.org/acs\" index=\"1\"")
			.contains("ResponseLocation=\"https://rp.example.org/logout/saml2/response\"");
	}

	@Test
	public void resolveWhenRelyingPartyNameIDFormatThenMetadataMatches() {
		RelyingPartyRegistration relyingPartyRegistration = TestRelyingPartyRegistrations.full()
			.nameIdFormat("format")
			.build();
		OpenSamlMetadataResolver openSamlMetadataResolver = new OpenSamlMetadataResolver();
		String metadata = openSamlMetadataResolver.resolve(relyingPartyRegistration);
		assertThat(metadata).contains("<md:NameIDFormat>format</md:NameIDFormat>");
	}

	@Test
	public void resolveWhenRelyingPartyNoLogoutThenMetadataMatches() {
		RelyingPartyRegistration relyingPartyRegistration = TestRelyingPartyRegistrations.full()
			.singleLogoutServiceLocation(null)
			.nameIdFormat("format")
			.build();
		OpenSamlMetadataResolver openSamlMetadataResolver = new OpenSamlMetadataResolver();
		String metadata = openSamlMetadataResolver.resolve(relyingPartyRegistration);
		assertThat(metadata).doesNotContain("ResponseLocation");
	}

	@Test
	public void resolveWhenEntityDescriptorCustomizerThenUses() {
		RelyingPartyRegistration relyingPartyRegistration = TestRelyingPartyRegistrations.full()
			.entityId("originalEntityId")
			.build();
		OpenSamlMetadataResolver openSamlMetadataResolver = new OpenSamlMetadataResolver();
		openSamlMetadataResolver.setEntityDescriptorCustomizer(
				(parameters) -> parameters.getEntityDescriptor().setEntityID("overriddenEntityId"));
		String metadata = openSamlMetadataResolver.resolve(relyingPartyRegistration);
		assertThat(metadata).contains("<md:EntityDescriptor").contains("entityID=\"overriddenEntityId\"");
	}

	@Test
	public void resolveIterableWhenRelyingPartiesThenMetadataMatches() {
		RelyingPartyRegistration one = TestRelyingPartyRegistrations.full()
			.assertionConsumerServiceBinding(Saml2MessageBinding.REDIRECT)
			.build();
		RelyingPartyRegistration two = TestRelyingPartyRegistrations.full()
			.entityId("two")
			.assertionConsumerServiceBinding(Saml2MessageBinding.REDIRECT)
			.build();
		OpenSamlMetadataResolver openSamlMetadataResolver = new OpenSamlMetadataResolver();
		String metadata = openSamlMetadataResolver.resolve(List.of(one, two));
		assertThat(metadata).contains("<md:EntitiesDescriptor")
			.contains("<md:EntityDescriptor")
			.contains("entityID=\"rp-entity-id\"")
			.contains("entityID=\"two\"")
			.contains("<md:KeyDescriptor use=\"signing\">")
			.contains("<md:KeyDescriptor use=\"encryption\">")
			.contains("<ds:X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBh")
			.contains("Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"")
			.contains("Location=\"https://rp.example.org/acs\" index=\"1\"")
			.contains("ResponseLocation=\"https://rp.example.org/logout/saml2/response\"");
	}

	@Test
	public void resolveIterableWhenRelyingPartiesAndSignMetadataSetThenMetadataMatches() {
		RelyingPartyRegistration one = TestRelyingPartyRegistrations.full()
			.assertionConsumerServiceBinding(Saml2MessageBinding.REDIRECT)
			.build();
		RelyingPartyRegistration two = TestRelyingPartyRegistrations.full()
			.entityId("two")
			.assertionConsumerServiceBinding(Saml2MessageBinding.REDIRECT)
			.build();
		OpenSamlMetadataResolver openSamlMetadataResolver = new OpenSamlMetadataResolver();
		openSamlMetadataResolver.setSignMetadata(true);
		String metadata = openSamlMetadataResolver.resolve(List.of(one, two));
		assertThat(metadata).contains("<md:EntitiesDescriptor")
			.contains("<md:EntityDescriptor")
			.contains("entityID=\"rp-entity-id\"")
			.contains("entityID=\"two\"")
			.contains("<md:KeyDescriptor use=\"signing\">")
			.contains("<md:KeyDescriptor use=\"encryption\">")
			.contains("<ds:X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBh")
			.contains("Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"")
			.contains("Location=\"https://rp.example.org/acs\" index=\"1\"")
			.contains("ResponseLocation=\"https://rp.example.org/logout/saml2/response\"")
			.contains("Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"")
			.contains("CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#")
			.contains("SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
			.contains("Reference URI=\"\"")
			.contains("Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature")
			.contains("Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"")
			.contains("DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"")
			.contains("DigestValue")
			.contains("SignatureValue");
	}

}
