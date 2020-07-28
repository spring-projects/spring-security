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

import org.junit.Test;

import org.springframework.security.saml2.credentials.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;

import static org.assertj.core.api.Assertions.assertThat;

public class RelyingPartyRegistrationTests {

	@Test
	public void withRelyingPartyRegistrationWorks() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.relyingPartyRegistration()
				.providerDetails(p -> p.binding(Saml2MessageBinding.POST))
				.providerDetails(p -> p.signAuthNRequest(false))
				.assertionConsumerServiceBinding(Saml2MessageBinding.REDIRECT).build();
		RelyingPartyRegistration copy = RelyingPartyRegistration.withRelyingPartyRegistration(registration).build();
		compareRegistrations(registration, copy);
	}

	private void compareRegistrations(RelyingPartyRegistration registration, RelyingPartyRegistration copy) {
		assertThat(copy.getRegistrationId()).isEqualTo(registration.getRegistrationId()).isEqualTo("simplesamlphp");
		assertThat(copy.getProviderDetails().getEntityId()).isEqualTo(registration.getProviderDetails().getEntityId())
				.isEqualTo(copy.getAssertingPartyDetails().getEntityId())
				.isEqualTo(registration.getAssertingPartyDetails().getEntityId())
				.isEqualTo("https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php");
		assertThat(copy.getAssertionConsumerServiceUrlTemplate())
				.isEqualTo(registration.getAssertionConsumerServiceUrlTemplate())
				.isEqualTo(copy.getAssertionConsumerServiceLocation())
				.isEqualTo(registration.getAssertionConsumerServiceLocation())
				.isEqualTo("{baseUrl}" + Saml2WebSsoAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI);
		assertThat(copy.getCredentials()).containsAll(registration.getCredentials())
				.containsExactly(registration.getCredentials().get(0), registration.getCredentials().get(1));
		assertThat(copy.getLocalEntityIdTemplate()).isEqualTo(registration.getLocalEntityIdTemplate())
				.isEqualTo(copy.getEntityId()).isEqualTo(registration.getEntityId())
				.isEqualTo("{baseUrl}/saml2/service-provider-metadata/{registrationId}");
		assertThat(copy.getProviderDetails().getWebSsoUrl()).isEqualTo(registration.getProviderDetails().getWebSsoUrl())
				.isEqualTo(copy.getAssertingPartyDetails().getSingleSignOnServiceLocation())
				.isEqualTo(registration.getAssertingPartyDetails().getSingleSignOnServiceLocation())
				.isEqualTo("https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SSOService.php");
		assertThat(copy.getProviderDetails().getBinding()).isEqualTo(registration.getProviderDetails().getBinding())
				.isEqualTo(copy.getAssertingPartyDetails().getSingleSignOnServiceBinding())
				.isEqualTo(registration.getAssertingPartyDetails().getSingleSignOnServiceBinding())
				.isEqualTo(Saml2MessageBinding.POST);
		assertThat(copy.getProviderDetails().isSignAuthNRequest())
				.isEqualTo(registration.getProviderDetails().isSignAuthNRequest())
				.isEqualTo(copy.getAssertingPartyDetails().getWantAuthnRequestsSigned())
				.isEqualTo(registration.getAssertingPartyDetails().getWantAuthnRequestsSigned()).isFalse();
		assertThat(copy.getAssertionConsumerServiceBinding())
				.isEqualTo(registration.getAssertionConsumerServiceBinding());
		assertThat(copy.getDecryptionX509Credentials()).isEqualTo(registration.getDecryptionX509Credentials());
		assertThat(copy.getSigningX509Credentials()).isEqualTo(registration.getSigningX509Credentials());
		assertThat(copy.getAssertingPartyDetails().getEncryptionX509Credentials())
				.isEqualTo(registration.getAssertingPartyDetails().getEncryptionX509Credentials());
		assertThat(copy.getAssertingPartyDetails().getVerificationX509Credentials())
				.isEqualTo(registration.getAssertingPartyDetails().getVerificationX509Credentials());
	}

	@Test
	public void buildWhenUsingDefaultsThenAssertionConsumerServiceBindingDefaultsToPost() {
		RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistration.withRegistrationId("id")
				.entityId("entity-id").assertionConsumerServiceLocation("location")
				.assertingPartyDetails(
						assertingParty -> assertingParty.entityId("entity-id").singleSignOnServiceLocation("location"))
				.credentials(c -> c.add(TestSaml2X509Credentials.relyingPartyVerifyingCredential())).build();

		assertThat(relyingPartyRegistration.getAssertionConsumerServiceBinding()).isEqualTo(Saml2MessageBinding.POST);
	}

}
