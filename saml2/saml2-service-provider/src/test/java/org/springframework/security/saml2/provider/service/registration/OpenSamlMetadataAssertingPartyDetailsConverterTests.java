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

package org.springframework.security.saml2.provider.service.registration;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import org.springframework.security.saml2.Saml2Exception;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

public class OpenSamlMetadataAssertingPartyDetailsConverterTests {

	private static final String CERTIFICATE = "MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk";

	private static final String ENTITIES_DESCRIPTOR_TEMPLATE = "<md:EntitiesDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">\n%s</md:EntitiesDescriptor>";

	private static final String ENTITY_DESCRIPTOR_TEMPLATE = "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" "
			+ "xmlns:alg=\"urn:oasis:names:tc:SAML:metadata:algsupport\" " + "entityID=\"entity-id\" "
			+ "ID=\"_bf133aac099b99b3d81286e1a341f2d34188043a77fe15bf4bf1487dae9b2ea3\">\n%s"
			+ "</md:EntityDescriptor>";

	private static final String IDP_SSO_DESCRIPTOR_TEMPLATE = "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n"
			+ "%s\n" + "</md:IDPSSODescriptor>";

	private static final String KEY_DESCRIPTOR_TEMPLATE = "<md:KeyDescriptor %s>\n"
			+ "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" + "<ds:X509Data>\n"
			+ "<ds:X509Certificate>" + CERTIFICATE + "</ds:X509Certificate>\n" + "</ds:X509Data>\n" + "</ds:KeyInfo>\n"
			+ "</md:KeyDescriptor>";

	private static final String EXTENSIONS_TEMPLATE = "<md:Extensions>" + "<alg:SigningMethod Algorithm=\""
			+ SignatureConstants.ALGO_ID_DIGEST_SHA512 + "\"/>" + "</md:Extensions>";

	private static final String SINGLE_SIGN_ON_SERVICE_TEMPLATE = "<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" "
			+ "Location=\"sso-location\"/>";

	private OpenSamlMetadataAssertingPartyDetailsConverter converter;

	@BeforeEach
	public void setup() {
		this.converter = new OpenSamlMetadataAssertingPartyDetailsConverter();
	}

	@Test
	public void readWhenMissingIDPSSODescriptorThenException() {
		String payload = String.format(ENTITY_DESCRIPTOR_TEMPLATE, "");
		InputStream inputStream = new ByteArrayInputStream(payload.getBytes());
		assertThatExceptionOfType(Saml2Exception.class).isThrownBy(() -> this.converter.convert(inputStream))
				.withMessageContaining("Metadata response is missing the necessary IDPSSODescriptor element");
	}

	@Test
	public void readWhenMissingVerificationKeyThenException() {
		String payload = String.format(ENTITY_DESCRIPTOR_TEMPLATE, String.format(IDP_SSO_DESCRIPTOR_TEMPLATE, ""));
		InputStream inputStream = new ByteArrayInputStream(payload.getBytes());
		assertThatExceptionOfType(Saml2Exception.class).isThrownBy(() -> this.converter.convert(inputStream))
				.withMessageContaining(
						"Metadata response is missing verification certificates, necessary for verifying SAML assertions");
	}

	@Test
	public void readWhenMissingSingleSignOnServiceThenException() {
		String payload = String.format(ENTITY_DESCRIPTOR_TEMPLATE,
				String.format(IDP_SSO_DESCRIPTOR_TEMPLATE, String.format(KEY_DESCRIPTOR_TEMPLATE, "use=\"signing\"")));
		InputStream inputStream = new ByteArrayInputStream(payload.getBytes());
		assertThatExceptionOfType(Saml2Exception.class).isThrownBy(() -> this.converter.convert(inputStream))
				.withMessageContaining(
						"Metadata response is missing a SingleSignOnService, necessary for sending AuthnRequests");
	}

	@Test
	public void readWhenDescriptorFullySpecifiedThenConfigures() throws Exception {
		String payload = String.format(ENTITY_DESCRIPTOR_TEMPLATE,
				String.format(IDP_SSO_DESCRIPTOR_TEMPLATE,
						String.format(KEY_DESCRIPTOR_TEMPLATE, "use=\"signing\"")
								+ String.format(KEY_DESCRIPTOR_TEMPLATE, "use=\"encryption\"") + EXTENSIONS_TEMPLATE
								+ String.format(SINGLE_SIGN_ON_SERVICE_TEMPLATE)));
		InputStream inputStream = new ByteArrayInputStream(payload.getBytes());
		RelyingPartyRegistration.AssertingPartyDetails details = this.converter.convert(inputStream).iterator().next()
				.build();
		assertThat(details.getWantAuthnRequestsSigned()).isFalse();
		assertThat(details.getSigningAlgorithms()).containsExactly(SignatureConstants.ALGO_ID_DIGEST_SHA512);
		assertThat(details.getSingleSignOnServiceLocation()).isEqualTo("sso-location");
		assertThat(details.getSingleSignOnServiceBinding()).isEqualTo(Saml2MessageBinding.REDIRECT);
		assertThat(details.getEntityId()).isEqualTo("entity-id");
		assertThat(details.getVerificationX509Credentials()).hasSize(1);
		assertThat(details.getVerificationX509Credentials().iterator().next().getCertificate())
				.isEqualTo(x509Certificate(CERTIFICATE));
		assertThat(details.getEncryptionX509Credentials()).hasSize(1);
		assertThat(details.getEncryptionX509Credentials().iterator().next().getCertificate())
				.isEqualTo(x509Certificate(CERTIFICATE));
		assertThat(details).isInstanceOf(OpenSamlAssertingPartyDetails.class);
		OpenSamlAssertingPartyDetails openSamlDetails = (OpenSamlAssertingPartyDetails) details;
		EntityDescriptor entityDescriptor = openSamlDetails.getEntityDescriptor();
		assertThat(entityDescriptor).isNotNull();
		assertThat(entityDescriptor.getEntityID()).isEqualTo(details.getEntityId());
	}

	// gh-9051
	@Test
	public void readWhenEntitiesDescriptorThenConfigures() throws Exception {
		String payload = String.format(ENTITIES_DESCRIPTOR_TEMPLATE,
				String.format(ENTITY_DESCRIPTOR_TEMPLATE,
						String.format(IDP_SSO_DESCRIPTOR_TEMPLATE,
								String.format(KEY_DESCRIPTOR_TEMPLATE, "use=\"signing\"")
										+ String.format(KEY_DESCRIPTOR_TEMPLATE, "use=\"encryption\"")
										+ String.format(SINGLE_SIGN_ON_SERVICE_TEMPLATE))));
		InputStream inputStream = new ByteArrayInputStream(payload.getBytes());
		RelyingPartyRegistration.AssertingPartyDetails details = this.converter.convert(inputStream).iterator().next()
				.build();
		assertThat(details.getWantAuthnRequestsSigned()).isFalse();
		assertThat(details.getSingleSignOnServiceLocation()).isEqualTo("sso-location");
		assertThat(details.getSingleSignOnServiceBinding()).isEqualTo(Saml2MessageBinding.REDIRECT);
		assertThat(details.getEntityId()).isEqualTo("entity-id");
		assertThat(details.getVerificationX509Credentials()).hasSize(1);
		assertThat(details.getVerificationX509Credentials().iterator().next().getCertificate())
				.isEqualTo(x509Certificate(CERTIFICATE));
		assertThat(details.getEncryptionX509Credentials()).hasSize(1);
		assertThat(details.getEncryptionX509Credentials().iterator().next().getCertificate())
				.isEqualTo(x509Certificate(CERTIFICATE));
	}

	@Test
	public void readWhenKeyDescriptorHasNoUseThenConfiguresBothKeyTypes() throws Exception {
		String payload = String.format(ENTITY_DESCRIPTOR_TEMPLATE, String.format(IDP_SSO_DESCRIPTOR_TEMPLATE,
				String.format(KEY_DESCRIPTOR_TEMPLATE, "") + String.format(SINGLE_SIGN_ON_SERVICE_TEMPLATE)));
		InputStream inputStream = new ByteArrayInputStream(payload.getBytes());
		RelyingPartyRegistration.AssertingPartyDetails details = this.converter.convert(inputStream).iterator().next()
				.build();
		assertThat(details.getVerificationX509Credentials().iterator().next().getCertificate())
				.isEqualTo(x509Certificate(CERTIFICATE));
		assertThat(details.getEncryptionX509Credentials()).hasSize(1);
		assertThat(details.getEncryptionX509Credentials().iterator().next().getCertificate())
				.isEqualTo(x509Certificate(CERTIFICATE));
	}

	X509Certificate x509Certificate(String data) {
		try {
			InputStream certificate = new ByteArrayInputStream(Base64.getDecoder().decode(data.getBytes()));
			return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(certificate);
		}
		catch (Exception ex) {
			throw new IllegalArgumentException(ex);
		}
	}

	// gh-9051
	@Test
	public void readWhenUnsupportedElementThenSaml2Exception() {
		String payload = "<saml2:Assertion xmlns:saml2=\"https://some.endpoint\"/>";
		InputStream inputStream = new ByteArrayInputStream(payload.getBytes());
		assertThatExceptionOfType(Saml2Exception.class).isThrownBy(() -> this.converter.convert(inputStream))
				.withMessage("Unsupported element of type saml2:Assertion");
	}

}
