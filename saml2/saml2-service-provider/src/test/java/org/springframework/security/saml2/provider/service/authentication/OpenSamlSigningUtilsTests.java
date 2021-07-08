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

package org.springframework.security.saml2.provider.service.authentication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.xmlsec.signature.Signature;

import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test open SAML signatures
 */
public class OpenSamlSigningUtilsTests {

	private RelyingPartyRegistration registration;

	@BeforeEach
	public void setup() {
		this.registration = RelyingPartyRegistration.withRegistrationId("saml-idp")
				.entityId("https://some.idp.example.com/entity-id").signingX509Credentials((c) -> {
					c.add(TestSaml2X509Credentials.relyingPartySigningCredential());
					c.add(TestSaml2X509Credentials.assertingPartySigningCredential());
				}).assertingPartyDetails((c) -> c.entityId("https://some.idp.example.com/entity-id")
						.singleSignOnServiceLocation("https://some.idp.example.com/service-location"))
				.build();
	}

	@Test
	public void whenSigningAnObjectThenKeyInfoIsPartOfTheSignature() throws Exception {
		Response response = TestOpenSamlObjects.response();
		OpenSamlSigningUtils.sign(response, this.registration);
		Signature signature = response.getSignature();
		assertThat(signature).isNotNull();
		assertThat(signature.getKeyInfo()).isNotNull();
	}

}
