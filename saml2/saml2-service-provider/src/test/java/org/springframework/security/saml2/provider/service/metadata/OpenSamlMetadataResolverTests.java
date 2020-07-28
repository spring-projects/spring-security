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

package org.springframework.security.saml2.provider.service.metadata;

import org.junit.Test;

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
		// given
		RelyingPartyRegistration relyingPartyRegistration = TestRelyingPartyRegistrations.full()
				.assertionConsumerServiceBinding(Saml2MessageBinding.REDIRECT).build();
		OpenSamlMetadataResolver openSamlMetadataResolver = new OpenSamlMetadataResolver();

		// when
		String metadata = openSamlMetadataResolver.resolve(relyingPartyRegistration);

		// then
		assertThat(metadata).contains("<EntityDescriptor").contains("entityID=\"rp-entity-id\"")
				.contains("WantAssertionsSigned=\"true\"").contains("<md:KeyDescriptor use=\"signing\">")
				.contains("<md:KeyDescriptor use=\"encryption\">")
				.contains("<ds:X509Certificate>MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBh")
				.contains("Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"")
				.contains("Location=\"https://rp.example.org/acs\" index=\"1\"");
	}

	@Test
	public void resolveWhenRelyingPartyNoCredentialsThenMetadataMatches() {
		// given
		RelyingPartyRegistration relyingPartyRegistration = TestRelyingPartyRegistrations.noCredentials()
				.assertingPartyDetails(party -> party.verificationX509Credentials(
						c -> c.add(TestSaml2X509Credentials.relyingPartyVerifyingCredential())))
				.build();
		OpenSamlMetadataResolver openSamlMetadataResolver = new OpenSamlMetadataResolver();

		// when
		String metadata = openSamlMetadataResolver.resolve(relyingPartyRegistration);

		// then
		assertThat(metadata).contains("<EntityDescriptor").contains("entityID=\"rp-entity-id\"")
				.contains("WantAssertionsSigned=\"true\"").doesNotContain("<md:KeyDescriptor use=\"signing\">")
				.doesNotContain("<md:KeyDescriptor use=\"encryption\">")
				.contains("Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"")
				.contains("Location=\"https://rp.example.org/acs\" index=\"1\"");
	}

}
