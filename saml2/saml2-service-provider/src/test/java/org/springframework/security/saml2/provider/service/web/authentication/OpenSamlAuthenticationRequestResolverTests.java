/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web.authentication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link OpenSamlAuthenticationRequestResolver}
 */
public class OpenSamlAuthenticationRequestResolverTests {

	private RelyingPartyRegistration.Builder relyingPartyRegistrationBuilder;

	@BeforeEach
	public void setUp() {
		this.relyingPartyRegistrationBuilder = TestRelyingPartyRegistrations.relyingPartyRegistration();
	}

	@Test
	public void resolveAuthenticationRequestWhenSignedRedirectThenSignsAndRedirects() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setPathInfo("/saml2/authenticate/registration-id");
		RelyingPartyRegistration registration = this.relyingPartyRegistrationBuilder.build();
		OpenSamlAuthenticationRequestResolver resolver = authenticationRequestResolver(registration);
		Saml2RedirectAuthenticationRequest result = resolver.resolve(request, (r, authnRequest) -> {
			assertThat(authnRequest.getAssertionConsumerServiceURL())
					.isEqualTo(registration.getAssertionConsumerServiceLocation());
			assertThat(authnRequest.getProtocolBinding())
					.isEqualTo(registration.getAssertionConsumerServiceBinding().getUrn());
			assertThat(authnRequest.getDestination())
					.isEqualTo(registration.getAssertingPartyDetails().getSingleSignOnServiceLocation());
			assertThat(authnRequest.getIssuer().getValue()).isEqualTo(registration.getEntityId());
		});
		assertThat(result.getSamlRequest()).isNotEmpty();
		assertThat(result.getRelayState()).isNotNull();
		assertThat(result.getSigAlg()).isEqualTo(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		assertThat(result.getSignature()).isNotEmpty();
		assertThat(result.getBinding()).isEqualTo(Saml2MessageBinding.REDIRECT);
		assertThat(result.getId()).isNotEmpty();
	}

	@Test
	public void resolveAuthenticationRequestWhenUnsignedRedirectThenRedirectsAndNoSignature() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setPathInfo("/saml2/authenticate/registration-id");
		RelyingPartyRegistration registration = this.relyingPartyRegistrationBuilder
				.assertingPartyDetails((party) -> party.wantAuthnRequestsSigned(false)).build();
		OpenSamlAuthenticationRequestResolver resolver = authenticationRequestResolver(registration);
		Saml2RedirectAuthenticationRequest result = resolver.resolve(request, (r, authnRequest) -> {
			assertThat(authnRequest.getAssertionConsumerServiceURL())
					.isEqualTo(registration.getAssertionConsumerServiceLocation());
			assertThat(authnRequest.getProtocolBinding())
					.isEqualTo(registration.getAssertionConsumerServiceBinding().getUrn());
			assertThat(authnRequest.getDestination())
					.isEqualTo(registration.getAssertingPartyDetails().getSingleSignOnServiceLocation());
			assertThat(authnRequest.getIssuer().getValue()).isEqualTo(registration.getEntityId());
		});
		assertThat(result.getSamlRequest()).isNotEmpty();
		assertThat(result.getRelayState()).isNotNull();
		assertThat(result.getSigAlg()).isNull();
		assertThat(result.getSignature()).isNull();
		assertThat(result.getBinding()).isEqualTo(Saml2MessageBinding.REDIRECT);
		assertThat(result.getId()).isNotEmpty();
	}

	@Test
	public void resolveAuthenticationRequestWhenSignedThenCredentialIsRequired() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setPathInfo("/saml2/authenticate/registration-id");
		Saml2X509Credential credential = TestSaml2X509Credentials.relyingPartyVerifyingCredential();
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.noCredentials()
				.assertingPartyDetails((party) -> party.verificationX509Credentials((c) -> c.add(credential))).build();
		OpenSamlAuthenticationRequestResolver resolver = authenticationRequestResolver(registration);
		assertThatExceptionOfType(Saml2Exception.class)
				.isThrownBy(() -> resolver.resolve(request, (r, authnRequest) -> {
				}));
	}

	@Test
	public void resolveAuthenticationRequestWhenUnsignedPostThenOnlyPosts() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setPathInfo("/saml2/authenticate/registration-id");
		RelyingPartyRegistration registration = this.relyingPartyRegistrationBuilder.assertingPartyDetails(
				(party) -> party.singleSignOnServiceBinding(Saml2MessageBinding.POST).wantAuthnRequestsSigned(false))
				.build();
		OpenSamlAuthenticationRequestResolver resolver = authenticationRequestResolver(registration);
		Saml2PostAuthenticationRequest result = resolver.resolve(request, (r, authnRequest) -> {
			assertThat(authnRequest.getAssertionConsumerServiceURL())
					.isEqualTo(registration.getAssertionConsumerServiceLocation());
			assertThat(authnRequest.getProtocolBinding())
					.isEqualTo(registration.getAssertionConsumerServiceBinding().getUrn());
			assertThat(authnRequest.getDestination())
					.isEqualTo(registration.getAssertingPartyDetails().getSingleSignOnServiceLocation());
			assertThat(authnRequest.getIssuer().getValue()).isEqualTo(registration.getEntityId());
		});
		assertThat(result.getSamlRequest()).isNotEmpty();
		assertThat(result.getRelayState()).isNotNull();
		assertThat(result.getBinding()).isEqualTo(Saml2MessageBinding.POST);
		assertThat(new String(Saml2Utils.samlDecode(result.getSamlRequest()))).doesNotContain("Signature");
		assertThat(result.getId()).isNotEmpty();
	}

	@Test
	public void resolveAuthenticationRequestWhenSignedPostThenSignsAndPosts() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setPathInfo("/saml2/authenticate/registration-id");
		RelyingPartyRegistration registration = this.relyingPartyRegistrationBuilder
				.assertingPartyDetails((party) -> party.singleSignOnServiceBinding(Saml2MessageBinding.POST)).build();
		OpenSamlAuthenticationRequestResolver resolver = authenticationRequestResolver(registration);
		Saml2PostAuthenticationRequest result = resolver.resolve(request, (r, authnRequest) -> {
			assertThat(authnRequest.getAssertionConsumerServiceURL())
					.isEqualTo(registration.getAssertionConsumerServiceLocation());
			assertThat(authnRequest.getProtocolBinding())
					.isEqualTo(registration.getAssertionConsumerServiceBinding().getUrn());
			assertThat(authnRequest.getDestination())
					.isEqualTo(registration.getAssertingPartyDetails().getSingleSignOnServiceLocation());
			assertThat(authnRequest.getIssuer().getValue()).isEqualTo(registration.getEntityId());
		});
		assertThat(result.getSamlRequest()).isNotEmpty();
		assertThat(result.getRelayState()).isNotNull();
		assertThat(result.getBinding()).isEqualTo(Saml2MessageBinding.POST);
		assertThat(new String(Saml2Utils.samlDecode(result.getSamlRequest()))).contains("Signature");
		assertThat(result.getId()).isNotEmpty();
	}

	@Test
	public void resolveAuthenticationRequestWhenSHA1SignRequestThenSigns() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setPathInfo("/saml2/authenticate/registration-id");
		RelyingPartyRegistration registration = this.relyingPartyRegistrationBuilder.assertingPartyDetails(
				(party) -> party.signingAlgorithms((algs) -> algs.add(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1)))
				.build();
		OpenSamlAuthenticationRequestResolver resolver = authenticationRequestResolver(registration);
		Saml2RedirectAuthenticationRequest result = resolver.resolve(request, (r, authnRequest) -> {
		});
		assertThat(result.getSamlRequest()).isNotEmpty();
		assertThat(result.getRelayState()).isNotNull();
		assertThat(result.getSigAlg()).isEqualTo(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		assertThat(result.getSignature()).isNotNull();
		assertThat(result.getBinding()).isEqualTo(Saml2MessageBinding.REDIRECT);
		assertThat(result.getId()).isNotEmpty();
	}

	private OpenSamlAuthenticationRequestResolver authenticationRequestResolver(RelyingPartyRegistration registration) {
		return new OpenSamlAuthenticationRequestResolver((request, id) -> registration);
	}

}
