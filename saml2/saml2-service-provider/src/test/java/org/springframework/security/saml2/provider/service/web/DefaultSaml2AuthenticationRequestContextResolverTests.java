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

package org.springframework.security.saml2.provider.service.web;

import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.springframework.security.saml2.credentials.TestSaml2X509Credentials.relyingPartyVerifyingCredential;

/**
 * Tests for {@link DefaultSaml2AuthenticationRequestContextResolver}
 *
 * @author Shazin Sadakath
 * @author Josh Cummings
 */
public class DefaultSaml2AuthenticationRequestContextResolverTests {

	private static final String ASSERTING_PARTY_SSO_URL = "https://idp.example.com/sso";

	private static final String RELYING_PARTY_SSO_URL = "https://sp.example.com/sso";

	private static final String ASSERTING_PARTY_ENTITY_ID = "asserting-party-entity-id";

	private static final String RELYING_PARTY_ENTITY_ID = "relying-party-entity-id";

	private static final String REGISTRATION_ID = "registration-id";

	private MockHttpServletRequest request;

	private RelyingPartyRegistration.Builder relyingPartyBuilder;

	private Saml2AuthenticationRequestContextResolver authenticationRequestContextResolver = new DefaultSaml2AuthenticationRequestContextResolver(
			new DefaultRelyingPartyRegistrationResolver(id -> relyingPartyBuilder.build()));

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.request.setPathInfo("/saml2/authenticate/registration-id");
		this.relyingPartyBuilder = RelyingPartyRegistration.withRegistrationId(REGISTRATION_ID)
				.localEntityIdTemplate(RELYING_PARTY_ENTITY_ID)
				.providerDetails(c -> c.entityId(ASSERTING_PARTY_ENTITY_ID))
				.providerDetails(c -> c.webSsoUrl(ASSERTING_PARTY_SSO_URL))
				.assertionConsumerServiceUrlTemplate(RELYING_PARTY_SSO_URL)
				.credentials(c -> c.add(relyingPartyVerifyingCredential()));
	}

	@Test
	public void resolveWhenRequestAndRelyingPartyNotNullThenCreateSaml2AuthenticationRequestContext() {
		this.request.addParameter("RelayState", "relay-state");
		Saml2AuthenticationRequestContext context = this.authenticationRequestContextResolver.resolve(this.request);

		assertThat(context).isNotNull();
		assertThat(context.getAssertionConsumerServiceUrl()).isEqualTo(RELYING_PARTY_SSO_URL);
		assertThat(context.getRelayState()).isEqualTo("relay-state");
		assertThat(context.getDestination()).isEqualTo(ASSERTING_PARTY_SSO_URL);
		assertThat(context.getIssuer()).isEqualTo(RELYING_PARTY_ENTITY_ID);
		assertThat(context.getRelyingPartyRegistration().getRegistrationId())
				.isSameAs(this.relyingPartyBuilder.build().getRegistrationId());
	}

	@Test
	public void resolveWhenAssertionConsumerServiceUrlTemplateContainsRegistrationIdThenResolves() {
		this.relyingPartyBuilder.assertionConsumerServiceLocation("/saml2/authenticate/{registrationId}");
		Saml2AuthenticationRequestContext context = this.authenticationRequestContextResolver.resolve(this.request);

		assertThat(context.getAssertionConsumerServiceUrl()).isEqualTo("/saml2/authenticate/registration-id");
	}

	@Test
	public void resolveWhenAssertionConsumerServiceUrlTemplateContainsBaseUrlThenResolves() {
		this.relyingPartyBuilder.assertionConsumerServiceLocation("{baseUrl}/saml2/authenticate/{registrationId}");
		Saml2AuthenticationRequestContext context = this.authenticationRequestContextResolver.resolve(this.request);

		assertThat(context.getAssertionConsumerServiceUrl())
				.isEqualTo("http://localhost/saml2/authenticate/registration-id");
	}

	@Test
	public void resolveWhenRelyingPartyNullThenException() {
		assertThatCode(() -> this.authenticationRequestContextResolver.resolve(null))
				.isInstanceOf(IllegalArgumentException.class);
	}

}
