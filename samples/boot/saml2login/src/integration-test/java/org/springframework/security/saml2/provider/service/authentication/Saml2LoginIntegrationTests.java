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

package org.springframework.security.saml2.provider.service.authentication;

import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.UUID;
import javax.servlet.http.HttpSession;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import org.hamcrest.Matcher;
import org.joda.time.DateTime;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.crypto.KeySupport;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.AssertionErrors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.matchesRegex;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.security.saml2.provider.service.authentication.OpenSamlActionTestingSupport.buildConditions;
import static org.springframework.security.saml2.provider.service.authentication.OpenSamlActionTestingSupport.buildIssuer;
import static org.springframework.security.saml2.provider.service.authentication.OpenSamlActionTestingSupport.buildSubject;
import static org.springframework.security.saml2.provider.service.authentication.OpenSamlActionTestingSupport.buildSubjectConfirmation;
import static org.springframework.security.saml2.provider.service.authentication.OpenSamlActionTestingSupport.buildSubjectConfirmationData;
import static org.springframework.security.saml2.provider.service.authentication.OpenSamlActionTestingSupport.encryptNameId;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.security.web.WebAttributes.AUTHENTICATION_EXCEPTION;
import static org.springframework.test.util.AssertionErrors.assertEquals;
import static org.springframework.test.util.AssertionErrors.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class Saml2LoginIntegrationTests {

	static final String LOCAL_SP_ENTITY_ID = "http://localhost:8080/saml2/service-provider-metadata/simplesamlphp";
	static final String USERNAME = "testuser@spring.security.saml";

	@Autowired
	MockMvc mockMvc;

	@SpringBootConfiguration
	@EnableAutoConfiguration
	public static class SpringBootApplicationTestConfig {

	}

	@Test
	public void applicationAccessWhenSingleProviderAndUnauthenticatedThenRedirectsToAuthNRequest() throws Exception {
		mockMvc.perform(get("http://localhost:8080/some/url"))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost:8080/saml2/authenticate/simplesamlphp"));
	}

	@Test
	public void authenticateRequestWhenUnauthenticatedThenRespondsWithRedirectAuthNRequestXML() throws Exception {
		mockMvc.perform(get("http://localhost:8080/saml2/authenticate/simplesamlphp"))
				.andExpect(status().is3xxRedirection())
				.andExpect(header().string("Location", startsWith("https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SSOService.php?SAMLRequest=")));
	}

	@Test
	public void authenticateRequestWhenRelayStateThenRespondsWithRedirectAndEncodedRelayState() throws Exception {
		mockMvc.perform(
				get("http://localhost:8080/saml2/authenticate/simplesamlphp")
						.param("RelayState", "relay state value with spaces")
						.param("OtherParam", "OtherParamValue")
						.param("OtherParam2", "OtherParamValue2")
		)
				.andExpect(status().is3xxRedirection())
				.andExpect(header().string("Location", startsWith("https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SSOService.php?SAMLRequest=")))
				.andExpect(header().string("Location", containsString("RelayState=relay%20state%20value%20with%20spaces")))
				//check order of parameters
				.andExpect(header().string("Location", matchesRegex(".*\\?SAMLRequest\\=.*\\&RelayState\\=.*\\&SigAlg\\=.*\\&Signature\\=.*")));

	}

	@Test
	public void authenticateRequestWhenWorkingThenDestinationAttributeIsSet() throws Exception {
		final String redirectedUrl = mockMvc.perform(get("http://localhost:8080/saml2/authenticate/simplesamlphp"))
				.andExpect(status().is3xxRedirection())
				.andReturn()
				.getResponse()
				.getRedirectedUrl();
		MultiValueMap<String, String> parameters =
				UriComponentsBuilder.fromUriString(redirectedUrl).build(true).getQueryParams();
		String request = parameters.getFirst("SAMLRequest");
		AssertionErrors.assertNotNull("SAMLRequest parameter is missing", request);
		request = URLDecoder.decode(request);
		request = Saml2Utils.samlInflate(Saml2Utils.samlDecode(request));
		AuthnRequest authnRequest = (AuthnRequest) fromXml(request);
		String destination = authnRequest.getDestination();
		assertEquals(
				"Destination must match",
				"https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SSOService.php",
				destination
		);
		String acsURL = authnRequest.getAssertionConsumerServiceURL();
		assertEquals(
				"AssertionConsumerServiceURL must match",
				"http://localhost:8080/login/saml2/sso/simplesamlphp",
				acsURL
		);

	}


	@Test
	public void authenticateWhenResponseIsSignedThenItSucceeds() throws Exception {
		Assertion assertion = buildAssertion(USERNAME);
		Response response = buildResponse(assertion);
		signXmlObject(response, getSigningCredential(idpCertificate, idpPrivateKey, UsageType.SIGNING));
		sendResponse(response, "/")
				.andExpect(authenticated().withUsername(USERNAME));
	}

	@Test
	public void authenticateWhenAssertionIsThenItSignedSucceeds() throws Exception {
		Assertion assertion = buildAssertion(USERNAME);
		Response response = buildResponse(assertion);
		signXmlObject(assertion, getSigningCredential(idpCertificate, idpPrivateKey, UsageType.SIGNING));
		sendResponse(response, "/")
				.andExpect(authenticated().withUsername(USERNAME));
	}

	@Test
	public void authenticateWhenXmlObjectIsNotSignedThenItFails() throws Exception {
		Assertion assertion = buildAssertion(USERNAME);
		Response response = buildResponse(assertion);
		sendResponse(response, "/login?error")
				.andExpect(unauthenticated());
	}

	@Test
	public void authenticateWhenResponseIsSignedAndAssertionIsEncryptedThenItSucceeds() throws Exception {
		Assertion assertion = buildAssertion(USERNAME);
		EncryptedAssertion encryptedAssertion =
				OpenSamlActionTestingSupport.encryptAssertion(assertion, decodeCertificate(spCertificate));
		Response response = buildResponse(encryptedAssertion);
		signXmlObject(response, getSigningCredential(idpCertificate, idpPrivateKey, UsageType.SIGNING));
		sendResponse(response, "/")
				.andExpect(authenticated().withUsername(USERNAME));
	}

	@Test
	public void authenticateWhenResponseIsNotSignedAndAssertionIsEncryptedAndSignedThenItSucceeds() throws Exception {
		Assertion assertion = buildAssertion(USERNAME);
		signXmlObject(assertion, getSigningCredential(idpCertificate, idpPrivateKey, UsageType.SIGNING));
		EncryptedAssertion encryptedAssertion =
				OpenSamlActionTestingSupport.encryptAssertion(assertion, decodeCertificate(spCertificate));
		Response response = buildResponse(encryptedAssertion);
		sendResponse(response, "/")
				.andExpect(authenticated().withUsername(USERNAME));
	}

	@Test
	public void authenticateWhenResponseIsSignedAndNameIDisEncryptedThenItSucceeds() throws Exception {
		Assertion assertion = buildAssertion(USERNAME);
		final EncryptedID nameId = encryptNameId(assertion.getSubject().getNameID(), decodeCertificate(spCertificate));
		assertion.getSubject().setEncryptedID(nameId);
		assertion.getSubject().setNameID(null);
		Response response = buildResponse(assertion);
		signXmlObject(assertion, getSigningCredential(idpCertificate, idpPrivateKey, UsageType.SIGNING));
		sendResponse(response, "/")
				.andExpect(authenticated().withUsername(USERNAME));
	}

	@Test
	public void authenticateWhenSignatureKeysDontMatchThenItFails() throws Exception {
		Assertion assertion = buildAssertion(USERNAME);
		Response response = buildResponse(assertion);
		signXmlObject(assertion, getSigningCredential(spCertificate, spPrivateKey, UsageType.SIGNING));
		sendResponse(response, "/login?error")
				.andExpect(
						saml2AuthenticationExceptionMatcher(
								"invalid_signature",
								containsString("Invalid assertion [assertion] for SAML response")
						)
				);
	}

	@Test
	public void authenticateWhenNotOnOrAfterDontMatchThenItFails() throws Exception {
		Assertion assertion = buildAssertion(USERNAME);
		assertion.getConditions().setNotOnOrAfter(DateTime.now().minusDays(1));
		Response response = buildResponse(assertion);
		signXmlObject(assertion, getSigningCredential(idpCertificate, idpPrivateKey, UsageType.SIGNING));
		sendResponse(response, "/login?error")
				.andExpect(
						saml2AuthenticationExceptionMatcher(
								"invalid_assertion",
								containsString("Invalid assertion [assertion] for SAML response")
						)
				);
	}

	@Test
	public void authenticateWhenNotOnOrBeforeDontMatchThenItFails() throws Exception {
		Assertion assertion = buildAssertion(USERNAME);
		assertion.getConditions().setNotBefore(DateTime.now().plusDays(1));
		Response response = buildResponse(assertion);
		signXmlObject(assertion, getSigningCredential(idpCertificate, idpPrivateKey, UsageType.SIGNING));
		sendResponse(response, "/login?error")
				.andExpect(
						saml2AuthenticationExceptionMatcher(
								"invalid_assertion",
								containsString("Invalid assertion [assertion] for SAML response")
						)
				);
	}

	@Test
	public void authenticateWhenIssuerIsInvalidThenItFails() throws Exception {
		Assertion assertion = buildAssertion(USERNAME);
		Response response = buildResponse(assertion);
		response.getIssuer().setValue("invalid issuer");
		signXmlObject(response, getSigningCredential(idpCertificate, idpPrivateKey, UsageType.SIGNING));
		sendResponse(response, "/login?error")
				.andExpect(unauthenticated())
				.andExpect(
						saml2AuthenticationExceptionMatcher(
								"invalid_signature",
								containsString(
										"Invalid signature"
								)
						)
				);
	}

	private ResultActions sendResponse(
			Response response,
			String redirectUrl) throws Exception {
		String xml = toXml(response);
		return mockMvc.perform(post("http://localhost:8080/login/saml2/sso/simplesamlphp")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.param("SAMLResponse", Saml2Utils.samlEncode(xml.getBytes(UTF_8))))
				.andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl(redirectUrl));
	}

	private Response buildResponse(Assertion assertion) {
		Response response = buildResponse();
		response.getAssertions().add(assertion);
		return response;
	}

	private Response buildResponse(EncryptedAssertion assertion) {
		Response response = buildResponse();
		response.getEncryptedAssertions().add(assertion);
		return response;
	}

	private Response buildResponse() {
		Response response = OpenSamlActionTestingSupport.buildResponse();
		response.setID("_" + UUID.randomUUID().toString());
		response.setDestination("http://localhost:8080/login/saml2/sso/simplesamlphp");
		response.setIssuer(buildIssuer("https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php"));
		return response;
	}

	private Assertion buildAssertion(String username) {
		Assertion assertion = OpenSamlActionTestingSupport.buildAssertion();
		assertion.setIssueInstant(DateTime.now());
		assertion.setIssuer(buildIssuer("https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php"));
		assertion.setSubject(buildSubject(username));
		assertion.setConditions(buildConditions());

		SubjectConfirmation subjectConfirmation = buildSubjectConfirmation();

		// Default to bearer with basic valid confirmation data, but the test can change
		// as appropriate
		subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
		final SubjectConfirmationData confirmationData = buildSubjectConfirmationData(LOCAL_SP_ENTITY_ID);
		confirmationData.setRecipient("http://localhost:8080/login/saml2/sso/simplesamlphp");
		subjectConfirmation.setSubjectConfirmationData(confirmationData);
		assertion.getSubject().getSubjectConfirmations().add(subjectConfirmation);
		return assertion;
	}

	protected Credential getSigningCredential(String certificate, String key, UsageType usageType)
			throws CertificateException, KeyException {
		PublicKey publicKey = decodeCertificate(certificate).getPublicKey();
		final PrivateKey privateKey = KeySupport.decodePrivateKey(key.getBytes(UTF_8), new char[0]);
		BasicCredential cred = CredentialSupport.getSimpleCredential(publicKey, privateKey);
		cred.setUsageType(usageType);
		cred.setEntityId("https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php");
		return cred;
	}

	private void signXmlObject(SignableSAMLObject object, Credential credential)
			throws MarshallingException, SecurityException, SignatureException {
		SignatureSigningParameters parameters = new SignatureSigningParameters();
		parameters.setSigningCredential(credential);
		parameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
		parameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
		parameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		SignatureSupport.signObject(object, parameters);
	}

	private String toXml(XMLObject object) throws MarshallingException {
		final MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
		Element element = marshallerFactory.getMarshaller(object).marshall(object);
		return SerializeSupport.nodeToString(element);
	}

	private XMLObject fromXml(String xml)
			throws XMLParserException, UnmarshallingException, ComponentInitializationException {
		BasicParserPool parserPool = new BasicParserPool();
		parserPool.initialize();
		Document document = parserPool.parse(new ByteArrayInputStream(xml.getBytes(UTF_8)));
		Element element = document.getDocumentElement();
		return XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(element).unmarshall(element);

	}

	private X509Certificate decodeCertificate(String source) {
		try {
			final CertificateFactory factory = CertificateFactory.getInstance("X.509");
			return (X509Certificate) factory.generateCertificate(
					new ByteArrayInputStream(source.getBytes(StandardCharsets.UTF_8))
			);
		} catch (Exception e) {
			throw new IllegalArgumentException(e);
		}
	}

	private String idpCertificate = "-----BEGIN CERTIFICATE-----\n"
			+ "MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYD\n"
			+ "VQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYD\n"
			+ "VQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwX\n"
			+ "c2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0Bw\n"
			+ "aXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJ\n"
			+ "BgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAa\n"
			+ "BgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQD\n"
			+ "DBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlr\n"
			+ "QHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62\n"
			+ "E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz\n"
			+ "2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWW\n"
			+ "RDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQ\n"
			+ "nX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5\n"
			+ "cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gph\n"
			+ "iJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5\n"
			+ "ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTAD\n"
			+ "AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduO\n"
			+ "nRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+v\n"
			+ "ZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLu\n"
			+ "xbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6z\n"
			+ "V9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3\n"
			+ "lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk\n" + "-----END CERTIFICATE-----\n";

	private String idpPrivateKey = "-----BEGIN PRIVATE KEY-----\n"
			+ "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC4cn62E1xLqpN3\n"
			+ "4PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZX\n"
			+ "W+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHE\n"
			+ "fDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7h\n"
			+ "Z6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/T\n"
			+ "Xy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7\n"
			+ "I+J5lS8VAgMBAAECggEBAKyxBlIS7mcp3chvq0RF7B3PHFJMMzkwE+t3pLJcs4cZ\n"
			+ "nezh/KbREfP70QjXzk/llnZCvxeIs5vRu24vbdBm79qLHqBuHp8XfHHtuo2AfoAQ\n"
			+ "l4h047Xc/+TKMivnPQ0jX9qqndKDLqZDf5wnbslDmlskvF0a/MjsLU0TxtOfo+dB\n"
			+ "t55FW11cGqxZwhS5Gnr+cbw3OkHz23b9gEOt9qfwPVepeysbmm9FjU+k4yVa7rAN\n"
			+ "xcbzVb6Y7GCITe2tgvvEHmjB9BLmWrH3mZ3Af17YU/iN6TrpPd6Sj3QoS+2wGtAe\n"
			+ "HbUs3CKJu7bIHcj4poal6Kh8519S+erJTtqQ8M0ZiEECgYEA43hLYAPaUueFkdfh\n"
			+ "9K/7ClH6436CUH3VdizwUXi26fdhhV/I/ot6zLfU2mgEHU22LBECWQGtAFm8kv0P\n"
			+ "zPn+qjaR3e62l5PIlSYbnkIidzoDZ2ztu4jF5LgStlTJQPteFEGgZVl5o9DaSZOq\n"
			+ "Yd7G3XqXuQ1VGMW58G5FYJPtA1cCgYEAz5TPUtK+R2KXHMjUwlGY9AefQYRYmyX2\n"
			+ "Tn/OFgKvY8lpAkMrhPKONq7SMYc8E9v9G7A0dIOXvW7QOYSapNhKU+np3lUafR5F\n"
			+ "4ZN0bxZ9qjHbn3AMYeraKjeutHvlLtbHdIc1j3sxe/EzltRsYmiqLdEBW0p6hwWg\n"
			+ "tyGhYWVyaXMCgYAfDOKtHpmEy5nOCLwNXKBWDk7DExfSyPqEgSnk1SeS1HP5ctPK\n"
			+ "+1st6sIhdiVpopwFc+TwJWxqKdW18tlfT5jVv1E2DEnccw3kXilS9xAhWkfwrEvf\n"
			+ "V5I74GydewFl32o+NZ8hdo9GL1I8zO1rIq/et8dSOWGuWf9BtKu/vTGTTQKBgFxU\n"
			+ "VjsCnbvmsEwPUAL2hE/WrBFaKocnxXx5AFNt8lEyHtDwy4Sg1nygGcIJ4sD6koQk\n"
			+ "RdClT3LkvR04TAiSY80bN/i6ZcPNGUwSaDGZEWAIOSWbkwZijZNFnSGOEgxZX/IG\n"
			+ "yd39766vREEMTwEeiMNEOZQ/dmxkJm4OOVe25cLdAoGACOtPnq1Fxay80UYBf4rQ\n"
			+ "+bJ9yX1ulB8WIree1hD7OHSB2lRHxrVYWrglrTvkh63Lgx+EcsTV788OsvAVfPPz\n"
			+ "BZrn8SdDlQqalMxUBYEFwnsYD3cQ8yOUnijFVC4xNcdDv8OIqVgSk4KKxU5AshaA\n" + "xk6Mox+u8Cc2eAK12H13i+8=\n"
			+ "-----END PRIVATE KEY-----\n";

	private String spCertificate = "-----BEGIN CERTIFICATE-----\n" +
			"MIICgTCCAeoCCQCuVzyqFgMSyDANBgkqhkiG9w0BAQsFADCBhDELMAkGA1UEBhMC\n" +
			"VVMxEzARBgNVBAgMCldhc2hpbmd0b24xEjAQBgNVBAcMCVZhbmNvdXZlcjEdMBsG\n" +
			"A1UECgwUU3ByaW5nIFNlY3VyaXR5IFNBTUwxCzAJBgNVBAsMAnNwMSAwHgYDVQQD\n" +
			"DBdzcC5zcHJpbmcuc2VjdXJpdHkuc2FtbDAeFw0xODA1MTQxNDMwNDRaFw0yODA1\n" +
			"MTExNDMwNDRaMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjES\n" +
			"MBAGA1UEBwwJVmFuY291dmVyMR0wGwYDVQQKDBRTcHJpbmcgU2VjdXJpdHkgU0FN\n" +
			"TDELMAkGA1UECwwCc3AxIDAeBgNVBAMMF3NwLnNwcmluZy5zZWN1cml0eS5zYW1s\n" +
			"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRu7/EI0BlNzMEBFVAcbx+lLos\n" +
			"vzIWU+01dGTY8gBdhMQNYKZ92lMceo2CuVJ66cUURPym3i7nGGzoSnAxAre+0YIM\n" +
			"+U0razrWtAUE735bkcqELZkOTZLelaoOztmWqRbe5OuEmpewH7cx+kNgcVjdctOG\n" +
			"y3Q6x+I4qakY/9qhBQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAAeViTvHOyQopWEi\n" +
			"XOfI2Z9eukwrSknDwq/zscR0YxwwqDBMt/QdAODfSwAfnciiYLkmEjlozWRtOeN+\n" +
			"qK7UFgP1bRl5qksrYX5S0z2iGJh0GvonLUt3e20Ssfl5tTEDDnAEUMLfBkyaxEHD\n" +
			"RZ/nbTJ7VTeZOSyRoVn5XHhpuJ0B\n" +
			"-----END CERTIFICATE-----";

	private String spPrivateKey = "-----BEGIN PRIVATE KEY-----\n" +
			"MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBANG7v8QjQGU3MwQE\n" +
			"VUBxvH6Uuiy/MhZT7TV0ZNjyAF2ExA1gpn3aUxx6jYK5UnrpxRRE/KbeLucYbOhK\n" +
			"cDECt77Rggz5TStrOta0BQTvfluRyoQtmQ5Nkt6Vqg7O2ZapFt7k64Sal7AftzH6\n" +
			"Q2BxWN1y04bLdDrH4jipqRj/2qEFAgMBAAECgYEAj4ExY1jjdN3iEDuOwXuRB+Nn\n" +
			"x7pC4TgntE2huzdKvLJdGvIouTArce8A6JM5NlTBvm69mMepvAHgcsiMH1zGr5J5\n" +
			"wJz23mGOyhM1veON41/DJTVG+cxq4soUZhdYy3bpOuXGMAaJ8QLMbQQoivllNihd\n" +
			"vwH0rNSK8LTYWWPZYIECQQDxct+TFX1VsQ1eo41K0T4fu2rWUaxlvjUGhK6HxTmY\n" +
			"8OMJptunGRJL1CUjIb45Uz7SP8TPz5FwhXWsLfS182kRAkEA3l+Qd9C9gdpUh1uX\n" +
			"oPSNIxn5hFUrSTW1EwP9QH9vhwb5Vr8Jrd5ei678WYDLjUcx648RjkjhU9jSMzIx\n" +
			"EGvYtQJBAMm/i9NR7IVyyNIgZUpz5q4LI21rl1r4gUQuD8vA36zM81i4ROeuCly0\n" +
			"KkfdxR4PUfnKcQCX11YnHjk9uTFj75ECQEFY/gBnxDjzqyF35hAzrYIiMPQVfznt\n" +
			"YX/sDTE2AdVBVGaMj1Cb51bPHnNC6Q5kXKQnj/YrLqRQND09Q7ParX0CQQC5NxZr\n" +
			"9jKqhHj8yQD6PlXTsY4Occ7DH6/IoDenfdEVD5qlet0zmd50HatN2Jiqm5ubN7CM\n" +
			"INrtuLp4YHbgk1mi\n" +
			"-----END PRIVATE KEY-----";

	private static ResultMatcher saml2AuthenticationExceptionMatcher(
			String code,
			Matcher<String> message
	) {
		return (result) -> {
			final HttpSession session = result.getRequest().getSession(false);
			AssertionErrors.assertNotNull("HttpSession", session);
			Object exception = session.getAttribute(AUTHENTICATION_EXCEPTION);
			AssertionErrors.assertNotNull(AUTHENTICATION_EXCEPTION, exception);
			if (!(exception instanceof Saml2AuthenticationException)) {
				AssertionErrors.fail(
						"Invalid exception type",
						Saml2AuthenticationException.class,
						exception.getClass().getName()
				);
			}
			Saml2AuthenticationException se = (Saml2AuthenticationException) exception;
			assertEquals("SAML 2 Error Code", code, se.getError().getErrorCode());
			assertTrue("SAML 2 Error Description", message.matches(se.getError().getDescription()));
		};
	}
}
