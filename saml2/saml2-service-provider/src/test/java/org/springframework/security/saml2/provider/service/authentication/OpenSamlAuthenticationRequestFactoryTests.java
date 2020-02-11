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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.containsString;
import static org.springframework.security.saml2.provider.service.authentication.Saml2Utils.samlDecode;
import static org.springframework.security.saml2.provider.service.authentication.TestSaml2X509Credentials.relyingPartyCredentials;
import static org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding.POST;
import static org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding.REDIRECT;

/**
 * Tests for {@link OpenSamlAuthenticationRequestFactory}
 */
public class OpenSamlAuthenticationRequestFactoryTests {

	private OpenSamlAuthenticationRequestFactory factory;
	private Saml2AuthenticationRequestContext.Builder contextBuilder;
	private Saml2AuthenticationRequestContext context;

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Before
	public void setUp() {
		RelyingPartyRegistration registration = RelyingPartyRegistration.withRegistrationId("id")
				.assertionConsumerServiceUrlTemplate("template")
				.idpWebSsoUrl("https://destination/sso")
				.remoteIdpEntityId("remote-entity-id")
				.localEntityIdTemplate("local-entity-id")
				.credentials(c -> c.addAll(relyingPartyCredentials()))
				.build();
		contextBuilder = Saml2AuthenticationRequestContext.builder()
				.issuer("https://issuer")
				.relyingPartyRegistration(registration)
				.assertionConsumerServiceUrl("https://issuer/sso");
		context = contextBuilder.build();
		factory = new OpenSamlAuthenticationRequestFactory();
	}

	@Test
	public void createAuthenticationRequestWhenInvokingDeprecatedMethodThenReturnsXML() {
		Saml2AuthenticationRequest request = Saml2AuthenticationRequest.withAuthenticationRequestContext(context).build();
		String result = factory.createAuthenticationRequest(request);
		assertThat(result).startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<saml2p:AuthnRequest");
	}

	@Test
	public void createRedirectAuthenticationRequestWhenUsingContextThenAllValuesAreSet() {
		context = contextBuilder
				.relayState("Relay State Value")
				.build();
		Saml2RedirectAuthenticationRequest result = factory.createRedirectAuthenticationRequest(context);
		assertThat(result.getSamlRequest()).isNotEmpty();
		assertThat(result.getRelayState()).isEqualTo("Relay State Value");
		assertThat(result.getSigAlg()).isNotEmpty();
		assertThat(result.getSignature()).isNotEmpty();
		assertThat(result.getBinding()).isEqualTo(REDIRECT);
	}

	@Test
	public void createAuthenticationRequestWhenDefaultThenReturnsPostBinding() {
		AuthnRequest authn = getAuthNRequest(POST);
		Assert.assertEquals(SAMLConstants.SAML2_POST_BINDING_URI, authn.getProtocolBinding());
	}

	@Test
	public void createAuthenticationRequestWhenSetUriThenReturnsCorrectBinding() {
		factory.setProtocolBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		AuthnRequest authn = getAuthNRequest(POST);
		Assert.assertEquals(SAMLConstants.SAML2_REDIRECT_BINDING_URI, authn.getProtocolBinding());
	}

	@Test
	public void createAuthenticationRequestWhenSetUnsupportredUriThenThrowsIllegalArgumentException() {
		exception.expect(IllegalArgumentException.class);
		exception.expectMessage(containsString("my-invalid-binding"));
		factory.setProtocolBinding("my-invalid-binding");
	}

	private AuthnRequest getAuthNRequest(Saml2MessageBinding binding) {
		AbstractSaml2AuthenticationRequest result = (binding == REDIRECT) ?
				factory.createRedirectAuthenticationRequest(context) :
				factory.createPostAuthenticationRequest(context);
		String samlRequest = result.getSamlRequest();
		assertThat(samlRequest).isNotEmpty();
		if (result.getBinding() == REDIRECT) {
			samlRequest = Saml2Utils.samlInflate(samlDecode(samlRequest));
		}
		else {
			samlRequest = new String(samlDecode(samlRequest), StandardCharsets.UTF_8);
		}
		return (AuthnRequest) OpenSamlImplementation.getInstance().resolve(samlRequest);
	}
}
