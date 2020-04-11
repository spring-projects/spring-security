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

import static org.springframework.security.saml2.provider.service.servlet.filter.TestSaml2SigningCredentials.signingCredential;
import static org.assertj.core.api.Assertions.*;

public class DefaultSaml2AuthenticationRequestContextResolverTests {

	private static final String IDP_SSO_URL = "https://sso-url.example.com/IDP/SSO";
	private static final String TEMPLATE = "template";
	private static final String REGISTRATION_ID = "registration-id";
	private static final String IDP_ENTITY_ID = "idp-entity-id";

	private MockHttpServletRequest request;
	private RelyingPartyRegistration.Builder rpBuilder;
	private Saml2AuthenticationRequestContextResolver authenticationRequestContextResolver = new DefaultSaml2AuthenticationRequestContextResolver();

	@Before
	public void setup() {
		request = new MockHttpServletRequest();
		rpBuilder = RelyingPartyRegistration
				.withRegistrationId(REGISTRATION_ID)
				.providerDetails(c -> c.entityId(IDP_ENTITY_ID))
				.providerDetails(c -> c.webSsoUrl(IDP_SSO_URL))
				.assertionConsumerServiceUrlTemplate(TEMPLATE)
				.credentials(c -> c.add(signingCredential()));
	}

	@Test
	public void resoleWhenRequestAndRelyingPartyNotNullThenCreateSaml2AuthenticationRequestContext() {
		Saml2AuthenticationRequestContext authenticationRequestContext = authenticationRequestContextResolver.resolve(request, rpBuilder.build());

		assertThat(authenticationRequestContext).isNotNull();
		assertThat(authenticationRequestContext.getAssertionConsumerServiceUrl()).isEqualTo(TEMPLATE);
		assertThat(authenticationRequestContext.getRelyingPartyRegistration().getRegistrationId()).isEqualTo(REGISTRATION_ID);
		assertThat(authenticationRequestContext.getRelyingPartyRegistration().getProviderDetails().getEntityId()).isEqualTo(IDP_ENTITY_ID);
		assertThat(authenticationRequestContext.getRelyingPartyRegistration().getProviderDetails().getWebSsoUrl()).isEqualTo(IDP_SSO_URL);
		assertThat(authenticationRequestContext.getRelyingPartyRegistration().getCredentials()).isNotEmpty();
	}

	@Test(expected = IllegalArgumentException.class)
	public void resolveWhenRequestAndRelyingPartyNullThenException() {
		authenticationRequestContextResolver.resolve(null, null);
	}
}
