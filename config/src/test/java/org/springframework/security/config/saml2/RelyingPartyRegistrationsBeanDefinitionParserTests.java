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

package org.springframework.security.config.saml2;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link RelyingPartyRegistrationsBeanDefinitionParser}.
 *
 * @author Marcus da Coregio
 */
@ExtendWith(SpringTestContextExtension.class)
public class RelyingPartyRegistrationsBeanDefinitionParserTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/saml2/RelyingPartyRegistrationsBeanDefinitionParserTests";

	// @formatter:off
	private static final String METADATA_LOCATION_XML_CONFIG = "<b:beans xmlns:b=\"http://www.springframework.org/schema/beans\"\n" +
			"         xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n" +
			"         xmlns=\"http://www.springframework.org/schema/security\"\n" +
			"         xsi:schemaLocation=\"\n" +
			"\t\t\thttp://www.springframework.org/schema/security\n" +
			"\t\t\thttps://www.springframework.org/schema/security/spring-security.xsd\n" +
			"\t\t\thttp://www.springframework.org/schema/beans\n" +
			"\t\t\thttps://www.springframework.org/schema/beans/spring-beans.xsd\">\n" +
			"  \n" +
			"  <relying-party-registrations>\n" +
			"    <relying-party-registration registration-id=\"one\"\n" +
			"                                metadata-location=\"${metadata-location}\"/>\n" +
			"  </relying-party-registrations>\n" +
			"\n" +
			"</b:beans>\n";
	// @formatter:on

	// @formatter:off
	private static final String METADATA_RESPONSE = "<?xml version=\"1.0\"?>\n" +
			"<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/metadata.php\" ID=\"_e793a707d3e1a9ee6cbec7454fdad2c7cd793dd3703179a527b9620a6e9682af\"><ds:Signature>\n" +
			"  <ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\n" +
			"    <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>\n" +
			"  <ds:Reference URI=\"#_e793a707d3e1a9ee6cbec7454fdad2c7cd793dd3703179a527b9620a6e9682af\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>qIGOB+m2Kuq9Vp6F9qs/EFvFzuo6qEGukjICPyVAkjk=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>NgKak4k9LBAqbi8Za8ALUXW1l4npZ4+MOf8jhmpePDP3msbzjeKkkWFgxx+ILLJYwZzVWd3l028xm2l+SBOwoYRKJ670NgcdSdj6plBTGiZ5NXsXrX5M0zmgvAShREgjth/BKTUct5UVJOTqIxOPwBuCnj+Nn1+QUtY9ekPLrM0O2i+g1wckKaP6D7N+uVBwNgZGoOj5bZ082G7QXRX6Jo0925uKczAIKdIiBbMeKa/0phS2L97AkgQRGi2+j8V66TaDWuDSwd9hA2qzCwjsNui4DVLBwP0/LvgUdcu8g7JBIZ1yTddfByefOTVsU7UuZXkYEn4jU2ouk+u5klSo3Q==</ds:SignatureValue>\n" +
			"<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>\n" +
			"  <md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n" +
			"    <md:KeyDescriptor use=\"signing\">\n" +
			"      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
			"        <ds:X509Data>\n" +
			"          <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\n" +
			"        </ds:X509Data>\n" +
			"      </ds:KeyInfo>\n" +
			"    </md:KeyDescriptor>\n" +
			"    <md:KeyDescriptor use=\"encryption\">\n" +
			"      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
			"        <ds:X509Data>\n" +
			"          <ds:X509Certificate>MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk</ds:X509Certificate>\n" +
			"        </ds:X509Data>\n" +
			"      </ds:KeyInfo>\n" +
			"    </md:KeyDescriptor>\n" +
			"    <md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/SingleLogoutService.php\"/>\n" +
			"    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>\n" +
			"    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/SSOService.php\"/>\n" +
			"  </md:IDPSSODescriptor>\n" +
			"  <md:ContactPerson contactType=\"technical\">\n" +
			"    <md:GivenName>John</md:GivenName>\n" +
			"    <md:SurName>Doe</md:SurName>\n" +
			"    <md:EmailAddress>john@doe.com</md:EmailAddress>\n" +
			"  </md:ContactPerson>\n" +
			"</md:EntityDescriptor>\n";
	// @formatter:on

	@Autowired
	private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

	public final SpringTestContext spring = new SpringTestContext(this);

	private MockWebServer server;

	@AfterEach
	void cleanup() throws Exception {
		if (this.server != null) {
			this.server.shutdown();
		}
	}

	@Test
	public void parseWhenMetadataLocationConfiguredThenRequestMetadataFromLocation() throws Exception {
		this.server = new MockWebServer();
		this.server.start();
		String serverUrl = this.server.url("/").toString();
		this.server.enqueue(xmlResponse(METADATA_RESPONSE));
		String metadataConfig = METADATA_LOCATION_XML_CONFIG.replace("${metadata-location}", serverUrl);
		this.spring.context(metadataConfig).autowire();
		assertThat(this.relyingPartyRegistrationRepository)
				.isInstanceOf(InMemoryRelyingPartyRegistrationRepository.class);
		RelyingPartyRegistration relyingPartyRegistration = this.relyingPartyRegistrationRepository
				.findByRegistrationId("one");
		RelyingPartyRegistration.AssertingPartyDetails assertingPartyDetails = relyingPartyRegistration
				.getAssertingPartyDetails();
		assertThat(relyingPartyRegistration).isNotNull();
		assertThat(relyingPartyRegistration.getRegistrationId()).isEqualTo("one");
		assertThat(relyingPartyRegistration.getEntityId())
				.isEqualTo("{baseUrl}/saml2/service-provider-metadata/{registrationId}");
		assertThat(relyingPartyRegistration.getAssertionConsumerServiceLocation())
				.isEqualTo("{baseUrl}/login/saml2/sso/{registrationId}");
		assertThat(relyingPartyRegistration.getAssertionConsumerServiceBinding()).isEqualTo(Saml2MessageBinding.POST);
		assertThat(assertingPartyDetails.getEntityId())
				.isEqualTo("https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/metadata.php");
		assertThat(assertingPartyDetails.getWantAuthnRequestsSigned()).isFalse();
		assertThat(assertingPartyDetails.getVerificationX509Credentials()).hasSize(1);
		assertThat(assertingPartyDetails.getEncryptionX509Credentials()).hasSize(1);
		assertThat(assertingPartyDetails.getSingleSignOnServiceLocation())
				.isEqualTo("https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/SSOService.php");
		assertThat(assertingPartyDetails.getSingleSignOnServiceBinding()).isEqualTo(Saml2MessageBinding.REDIRECT);
		assertThat(assertingPartyDetails.getSigningAlgorithms())
				.containsExactly("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
	}

	@Test
	public void parseWhenSingleRelyingPartyRegistrationThenAvailableInRepository() {
		this.spring.configLocations(xml("SingleRegistration")).autowire();
		assertThat(this.relyingPartyRegistrationRepository)
				.isInstanceOf(InMemoryRelyingPartyRegistrationRepository.class);
		RelyingPartyRegistration relyingPartyRegistration = this.relyingPartyRegistrationRepository
				.findByRegistrationId("one");
		RelyingPartyRegistration.AssertingPartyDetails assertingPartyDetails = relyingPartyRegistration
				.getAssertingPartyDetails();
		assertThat(relyingPartyRegistration).isNotNull();
		assertThat(relyingPartyRegistration.getRegistrationId()).isEqualTo("one");
		assertThat(relyingPartyRegistration.getEntityId())
				.isEqualTo("{baseUrl}/saml2/service-provider-metadata/{registrationId}");
		assertThat(relyingPartyRegistration.getAssertionConsumerServiceLocation())
				.isEqualTo("{baseUrl}/login/saml2/sso/{registrationId}");
		assertThat(relyingPartyRegistration.getAssertionConsumerServiceBinding())
				.isEqualTo(Saml2MessageBinding.REDIRECT);
		assertThat(assertingPartyDetails.getEntityId()).isEqualTo("https://accounts.google.com/o/saml2/idp/entity-id");
		assertThat(assertingPartyDetails.getWantAuthnRequestsSigned()).isTrue();
		assertThat(assertingPartyDetails.getSingleSignOnServiceLocation())
				.isEqualTo("https://accounts.google.com/o/saml2/idp/sso-url");
		assertThat(assertingPartyDetails.getSingleSignOnServiceBinding()).isEqualTo(Saml2MessageBinding.POST);
		assertThat(assertingPartyDetails.getVerificationX509Credentials()).hasSize(1);
		assertThat(assertingPartyDetails.getEncryptionX509Credentials()).hasSize(1);
		assertThat(assertingPartyDetails.getSigningAlgorithms())
				.containsExactly("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
	}

	@Test
	public void parseWhenMultiRelyingPartyRegistrationThenAvailableInRepository() {
		this.spring.configLocations(xml("MultiRegistration")).autowire();
		assertThat(this.relyingPartyRegistrationRepository)
				.isInstanceOf(InMemoryRelyingPartyRegistrationRepository.class);
		RelyingPartyRegistration one = this.relyingPartyRegistrationRepository.findByRegistrationId("one");
		RelyingPartyRegistration.AssertingPartyDetails google = one.getAssertingPartyDetails();
		RelyingPartyRegistration two = this.relyingPartyRegistrationRepository.findByRegistrationId("two");
		RelyingPartyRegistration.AssertingPartyDetails simpleSaml = two.getAssertingPartyDetails();
		assertThat(one).isNotNull();
		assertThat(one.getRegistrationId()).isEqualTo("one");
		assertThat(one.getEntityId()).isEqualTo("{baseUrl}/saml2/service-provider-metadata/{registrationId}");
		assertThat(one.getAssertionConsumerServiceLocation()).isEqualTo("{baseUrl}/login/saml2/sso/{registrationId}");
		assertThat(one.getAssertionConsumerServiceBinding()).isEqualTo(Saml2MessageBinding.REDIRECT);
		assertThat(google.getEntityId()).isEqualTo("https://accounts.google.com/o/saml2/idp/entity-id");
		assertThat(google.getWantAuthnRequestsSigned()).isTrue();
		assertThat(google.getSingleSignOnServiceLocation())
				.isEqualTo("https://accounts.google.com/o/saml2/idp/sso-url");
		assertThat(google.getSingleSignOnServiceBinding()).isEqualTo(Saml2MessageBinding.POST);
		assertThat(google.getVerificationX509Credentials()).hasSize(1);
		assertThat(google.getEncryptionX509Credentials()).hasSize(1);
		assertThat(google.getSigningAlgorithms()).containsExactly("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
		assertThat(two).isNotNull();
		assertThat(two.getRegistrationId()).isEqualTo("two");
		assertThat(two.getEntityId()).isEqualTo("{baseUrl}/saml2/service-provider-metadata/{registrationId}");
		assertThat(two.getAssertionConsumerServiceLocation()).isEqualTo("{baseUrl}/login/saml2/sso/{registrationId}");
		assertThat(two.getAssertionConsumerServiceBinding()).isEqualTo(Saml2MessageBinding.POST);
		assertThat(simpleSaml.getEntityId())
				.isEqualTo("https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/metadata.php");
		assertThat(simpleSaml.getWantAuthnRequestsSigned()).isFalse();
		assertThat(simpleSaml.getSingleSignOnServiceLocation())
				.isEqualTo("https://simplesaml-for-spring-saml.apps.pcfone.io/saml2/idp/SSOService.php");
		assertThat(simpleSaml.getSingleSignOnServiceBinding()).isEqualTo(Saml2MessageBinding.POST);
		assertThat(simpleSaml.getVerificationX509Credentials()).hasSize(1);
		assertThat(simpleSaml.getEncryptionX509Credentials()).hasSize(1);
		assertThat(simpleSaml.getSigningAlgorithms()).containsExactly(
				"http://www.w3.org/2001/04/xmldsig-more#rsa-sha224",
				"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
				"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
	}

	private static MockResponse xmlResponse(String xml) {
		return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_XML_VALUE).setBody(xml);
	}

	private static String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

}
