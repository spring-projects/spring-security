/*
 * Copyright 2002-2019 the original author or authors.
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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;

import static org.hamcrest.CoreMatchers.containsString;
import static org.springframework.security.saml2.provider.service.authentication.TestSaml2X509Credentials.relyingPartyCredentials;

public class OpenSamlAuthenticationRequestFactoryTests {

	private OpenSamlAuthenticationRequestFactory factory;
	private Saml2AuthenticationRequest request;

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Before
	public void setUp() {
		request = Saml2AuthenticationRequest.builder()
				.issuer("https://issuer")
				.destination("https://destination/sso")
				.assertionConsumerServiceUrl("https://issuer/sso")
				.credentials(c -> c.addAll(relyingPartyCredentials()))
				.build();
		factory = new OpenSamlAuthenticationRequestFactory();
	}

	@Test
	public void createAuthenticationRequestWhenDefaultThenReturnsPostBinding() {
		AuthnRequest authn = getAuthNRequest();
		Assert.assertEquals(SAMLConstants.SAML2_POST_BINDING_URI, authn.getProtocolBinding());
	}

	@Test
	public void createAuthenticationRequestWhenSetUriThenReturnsCorrectBinding() {
		factory.setProtocolBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		AuthnRequest authn = getAuthNRequest();
		Assert.assertEquals(SAMLConstants.SAML2_REDIRECT_BINDING_URI, authn.getProtocolBinding());
	}

	@Test
	public void createAuthenticationRequestWhenSetUnsupportredUriThenThrowsIllegalArgumentException() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage(containsString("my-invalid-binding"));
		factory.setProtocolBinding("my-invalid-binding");
	}

	private AuthnRequest getAuthNRequest() {
		String xml = factory.createAuthenticationRequest(request);
		return (AuthnRequest) OpenSamlImplementation.getInstance().resolve(xml);
	}
}
