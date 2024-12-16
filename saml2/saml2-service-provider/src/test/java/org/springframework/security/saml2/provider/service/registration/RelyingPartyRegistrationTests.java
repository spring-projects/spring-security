/*
 * Copyright 2002-2023 the original author or authors.
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

import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration.AssertingPartyDetails;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class RelyingPartyRegistrationTests {

	@Test
	public void withRelyingPartyRegistrationWorks() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.relyingPartyRegistration()
			.nameIdFormat("format")
			.authnRequestsSigned(true)
			.assertingPartyDetails((a) -> a.singleSignOnServiceBinding(Saml2MessageBinding.POST))
			.assertingPartyDetails((a) -> a.wantAuthnRequestsSigned(false))
			.assertingPartyDetails((a) -> a.signingAlgorithms((algs) -> algs.add("alg")))
			.assertionConsumerServiceBinding(Saml2MessageBinding.REDIRECT)
			.build();
		RelyingPartyRegistration copy = RelyingPartyRegistration.withRelyingPartyRegistration(registration).build();
		compareRegistrations(registration, copy);
	}

	@Test
	void mutateWhenInvokedThenCreatesCopy() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.relyingPartyRegistration()
			.nameIdFormat("format")
			.assertingPartyDetails((a) -> a.singleSignOnServiceBinding(Saml2MessageBinding.POST))
			.assertingPartyDetails((a) -> a.wantAuthnRequestsSigned(false))
			.assertingPartyDetails((a) -> a.signingAlgorithms((algs) -> algs.add("alg")))
			.assertionConsumerServiceBinding(Saml2MessageBinding.REDIRECT)
			.build();
		RelyingPartyRegistration copy = registration.mutate().build();
		compareRegistrations(registration, copy);
	}

	private void compareRegistrations(RelyingPartyRegistration registration, RelyingPartyRegistration copy) {
		assertThat(copy.getRegistrationId()).isEqualTo(registration.getRegistrationId()).isEqualTo("simplesamlphp");
		assertThat(copy.getAssertingPartyDetails().getEntityId())
			.isEqualTo(registration.getAssertingPartyDetails().getEntityId())
			.isEqualTo("https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/metadata.php");
		assertThat(copy.getAssertionConsumerServiceLocation())
			.isEqualTo(registration.getAssertionConsumerServiceLocation())
			.isEqualTo("{baseUrl}" + Saml2WebSsoAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI);
		assertThat(copy.getSigningX509Credentials()).containsAll(registration.getSigningX509Credentials());
		assertThat(copy.getDecryptionX509Credentials()).containsAll(registration.getDecryptionX509Credentials());
		assertThat(copy.getEntityId()).isEqualTo(registration.getEntityId())
			.isEqualTo(copy.getEntityId())
			.isEqualTo(registration.getEntityId())
			.isEqualTo("{baseUrl}/saml2/service-provider-metadata/{registrationId}");
		assertThat(copy.getAssertingPartyDetails().getSingleSignOnServiceLocation())
			.isEqualTo(registration.getAssertingPartyDetails().getSingleSignOnServiceLocation())
			.isEqualTo("https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/SSOService.php");
		assertThat(copy.getAssertingPartyDetails().getSingleSignOnServiceBinding())
			.isEqualTo(registration.getAssertingPartyDetails().getSingleSignOnServiceBinding())
			.isEqualTo(Saml2MessageBinding.POST);
		assertThat(copy.getAssertingPartyDetails().getWantAuthnRequestsSigned())
			.isEqualTo(registration.getAssertingPartyDetails().getWantAuthnRequestsSigned())
			.isFalse();
		assertThat(copy.getAssertionConsumerServiceBinding())
			.isEqualTo(registration.getAssertionConsumerServiceBinding());
		assertThat(copy.getDecryptionX509Credentials()).isEqualTo(registration.getDecryptionX509Credentials());
		assertThat(copy.getSigningX509Credentials()).isEqualTo(registration.getSigningX509Credentials());
		assertThat(copy.getAssertingPartyDetails().getEncryptionX509Credentials())
			.isEqualTo(registration.getAssertingPartyDetails().getEncryptionX509Credentials());
		assertThat(copy.getAssertingPartyDetails().getVerificationX509Credentials())
			.isEqualTo(registration.getAssertingPartyDetails().getVerificationX509Credentials());
		assertThat(copy.getAssertingPartyDetails().getSigningAlgorithms())
			.isEqualTo(registration.getAssertingPartyDetails().getSigningAlgorithms());
		assertThat(copy.getNameIdFormat()).isEqualTo(registration.getNameIdFormat());
		assertThat(copy.isAuthnRequestsSigned()).isEqualTo(registration.isAuthnRequestsSigned());
	}

	@Test
	public void buildWhenUsingDefaultsThenAssertionConsumerServiceBindingDefaultsToPost() {
		RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistration.withRegistrationId("id")
			.entityId("entity-id")
			.assertionConsumerServiceLocation("location")
			.assertingPartyDetails((assertingParty) -> assertingParty.entityId("entity-id")
				.singleSignOnServiceLocation("location")
				.verificationX509Credentials((c) -> c.add(TestSaml2X509Credentials.relyingPartyVerifyingCredential())))
			.build();
		assertThat(relyingPartyRegistration.getAssertionConsumerServiceBinding()).isEqualTo(Saml2MessageBinding.POST);
	}

	@Test
	public void buildPreservesCredentialsOrder() {
		Saml2X509Credential altRpCredential = TestSaml2X509Credentials.altPrivateCredential();
		Saml2X509Credential altApCredential = TestSaml2X509Credentials.altPublicCredential();
		Saml2X509Credential verifyingCredential = TestSaml2X509Credentials.relyingPartyVerifyingCredential();
		Saml2X509Credential encryptingCredential = TestSaml2X509Credentials.relyingPartyEncryptingCredential();
		Saml2X509Credential signingCredential = TestSaml2X509Credentials.relyingPartySigningCredential();
		Saml2X509Credential decryptionCredential = TestSaml2X509Credentials.relyingPartyDecryptingCredential();

		// Test with the alt credentials first
		RelyingPartyRegistration relyingPartyRegistration = TestRelyingPartyRegistrations.noCredentials()
			.assertingPartyDetails((assertingParty) -> assertingParty.verificationX509Credentials((c) -> {
				c.add(altApCredential);
				c.add(verifyingCredential);
			}).encryptionX509Credentials((c) -> {
				c.add(altApCredential);
				c.add(encryptingCredential);
			}))
			.signingX509Credentials((c) -> {
				c.add(altRpCredential);
				c.add(signingCredential);
			})
			.decryptionX509Credentials((c) -> {
				c.add(altRpCredential);
				c.add(decryptionCredential);
			})
			.build();
		assertThat(relyingPartyRegistration.getSigningX509Credentials()).containsExactly(altRpCredential,
				signingCredential);
		assertThat(relyingPartyRegistration.getDecryptionX509Credentials()).containsExactly(altRpCredential,
				decryptionCredential);
		assertThat(relyingPartyRegistration.getAssertingPartyDetails().getVerificationX509Credentials())
			.containsExactly(altApCredential, verifyingCredential);
		assertThat(relyingPartyRegistration.getAssertingPartyDetails().getEncryptionX509Credentials())
			.containsExactly(altApCredential, encryptingCredential);

		// Test with the alt credentials last
		relyingPartyRegistration = TestRelyingPartyRegistrations.noCredentials()
			.assertingPartyDetails((assertingParty) -> assertingParty.verificationX509Credentials((c) -> {
				c.add(verifyingCredential);
				c.add(altApCredential);
			}).encryptionX509Credentials((c) -> {
				c.add(encryptingCredential);
				c.add(altApCredential);
			}))
			.signingX509Credentials((c) -> {
				c.add(signingCredential);
				c.add(altRpCredential);
			})
			.decryptionX509Credentials((c) -> {
				c.add(decryptionCredential);
				c.add(altRpCredential);
			})
			.build();
		assertThat(relyingPartyRegistration.getSigningX509Credentials()).containsExactly(signingCredential,
				altRpCredential);
		assertThat(relyingPartyRegistration.getDecryptionX509Credentials()).containsExactly(decryptionCredential,
				altRpCredential);
		assertThat(relyingPartyRegistration.getAssertingPartyDetails().getVerificationX509Credentials())
			.containsExactly(verifyingCredential, altApCredential);
		assertThat(relyingPartyRegistration.getAssertingPartyDetails().getEncryptionX509Credentials())
			.containsExactly(encryptingCredential, altApCredential);
	}

	@Test
	void withAssertingPartyMetadataWhenMetadataThenBuilderCopies() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.relyingPartyRegistration()
			.nameIdFormat("format")
			.assertingPartyMetadata((a) -> a.singleSignOnServiceBinding(Saml2MessageBinding.POST))
			.assertingPartyMetadata((a) -> a.wantAuthnRequestsSigned(false))
			.assertingPartyMetadata((a) -> a.signingAlgorithms((algs) -> algs.add("alg")))
			.assertionConsumerServiceBinding(Saml2MessageBinding.REDIRECT)
			.build();
		RelyingPartyRegistration copied = RelyingPartyRegistration
			.withAssertingPartyMetadata(registration.getAssertingPartyMetadata())
			.registrationId(registration.getRegistrationId())
			.entityId(registration.getEntityId())
			.signingX509Credentials((c) -> c.addAll(registration.getSigningX509Credentials()))
			.decryptionX509Credentials((c) -> c.addAll(registration.getDecryptionX509Credentials()))
			.assertionConsumerServiceLocation(registration.getAssertionConsumerServiceLocation())
			.assertionConsumerServiceBinding(registration.getAssertionConsumerServiceBinding())
			.singleLogoutServiceLocation(registration.getSingleLogoutServiceLocation())
			.singleLogoutServiceResponseLocation(registration.getSingleLogoutServiceResponseLocation())
			.singleLogoutServiceBindings((c) -> c.addAll(registration.getSingleLogoutServiceBindings()))
			.nameIdFormat(registration.getNameIdFormat())
			.authnRequestsSigned(registration.isAuthnRequestsSigned())
			.build();
		compareRegistrations(registration, copied);
	}

	@Test
	void withAssertingPartyMetadataWhenMetadataThenDisallowsDetails() {
		AssertingPartyMetadata metadata = new CustomAssertingPartyMetadata();
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> RelyingPartyRegistration.withAssertingPartyMetadata(metadata)
				.assertingPartyDetails((a) -> a.entityId("entity-id"))
				.build());
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(
				() -> RelyingPartyRegistration.withAssertingPartyMetadata(metadata).build().getAssertingPartyDetails());
	}

	@Test
	void withAssertingPartyMetadataWhenDetailsThenBuilderCopies() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.relyingPartyRegistration()
			.nameIdFormat("format")
			.assertingPartyMetadata((a) -> a.singleSignOnServiceBinding(Saml2MessageBinding.POST))
			.assertingPartyMetadata((a) -> a.wantAuthnRequestsSigned(false))
			.assertingPartyMetadata((a) -> a.signingAlgorithms((algs) -> algs.add("alg")))
			.assertionConsumerServiceBinding(Saml2MessageBinding.REDIRECT)
			.build();
		AssertingPartyDetails details = registration.getAssertingPartyDetails();
		RelyingPartyRegistration copied = RelyingPartyRegistration.withAssertingPartyDetails(details)
			.assertingPartyDetails((a) -> a.entityId(details.getEntityId()))
			.registrationId(registration.getRegistrationId())
			.entityId(registration.getEntityId())
			.signingX509Credentials((c) -> c.addAll(registration.getSigningX509Credentials()))
			.decryptionX509Credentials((c) -> c.addAll(registration.getDecryptionX509Credentials()))
			.assertionConsumerServiceLocation(registration.getAssertionConsumerServiceLocation())
			.assertionConsumerServiceBinding(registration.getAssertionConsumerServiceBinding())
			.singleLogoutServiceLocation(registration.getSingleLogoutServiceLocation())
			.singleLogoutServiceResponseLocation(registration.getSingleLogoutServiceResponseLocation())
			.singleLogoutServiceBindings((c) -> c.addAll(registration.getSingleLogoutServiceBindings()))
			.nameIdFormat(registration.getNameIdFormat())
			.authnRequestsSigned(registration.isAuthnRequestsSigned())
			.build();
		compareRegistrations(registration, copied);
	}

	private static class CustomAssertingPartyMetadata implements AssertingPartyMetadata {

		@Override
		public String getEntityId() {
			return "";
		}

		@Override
		public boolean getWantAuthnRequestsSigned() {
			return false;
		}

		@Override
		public List<String> getSigningAlgorithms() {
			return List.of();
		}

		@Override
		public Collection<Saml2X509Credential> getVerificationX509Credentials() {
			return List.of();
		}

		@Override
		public Collection<Saml2X509Credential> getEncryptionX509Credentials() {
			return List.of();
		}

		@Override
		public String getSingleSignOnServiceLocation() {
			return "";
		}

		@Override
		public Saml2MessageBinding getSingleSignOnServiceBinding() {
			return null;
		}

		@Override
		public String getSingleLogoutServiceLocation() {
			return "";
		}

		@Override
		public String getSingleLogoutServiceResponseLocation() {
			return "";
		}

		@Override
		public Saml2MessageBinding getSingleLogoutServiceBinding() {
			return null;
		}

		@Override
		public Builder mutate() {
			return new Builder();
		}

		private static class Builder implements AssertingPartyMetadata.Builder<Builder> {

			@Override
			public Builder entityId(String entityId) {
				return this;
			}

			@Override
			public Builder wantAuthnRequestsSigned(boolean wantAuthnRequestsSigned) {
				return this;
			}

			@Override
			public Builder signingAlgorithms(Consumer<List<String>> signingMethodAlgorithmsConsumer) {
				return this;
			}

			@Override
			public Builder verificationX509Credentials(Consumer<Collection<Saml2X509Credential>> credentialsConsumer) {
				return this;
			}

			@Override
			public Builder encryptionX509Credentials(Consumer<Collection<Saml2X509Credential>> credentialsConsumer) {
				return this;
			}

			@Override
			public Builder singleSignOnServiceLocation(String singleSignOnServiceLocation) {
				return this;
			}

			@Override
			public Builder singleSignOnServiceBinding(Saml2MessageBinding singleSignOnServiceBinding) {
				return this;
			}

			@Override
			public Builder singleLogoutServiceLocation(String singleLogoutServiceLocation) {
				return this;
			}

			@Override
			public Builder singleLogoutServiceResponseLocation(String singleLogoutServiceResponseLocation) {
				return this;
			}

			@Override
			public Builder singleLogoutServiceBinding(Saml2MessageBinding singleLogoutServiceBinding) {
				return this;
			}

			@Override
			public AssertingPartyMetadata build() {
				return new CustomAssertingPartyMetadata();
			}

		}

	}

}
