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

package org.springframework.security.saml2.provider.service.servlet.filter;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.saml2.provider.service.servlet.filter.TestSaml2SigningCredentials.signingCredential;

public class Saml2WebSsoAuthenticationRequestFilterTests {

	private Saml2WebSsoAuthenticationRequestFilter filter;
	private RelyingPartyRegistrationRepository repository = mock(RelyingPartyRegistrationRepository.class);
	private MockHttpServletRequest request;
	private HttpServletResponse response;
	private MockFilterChain filterChain;

	@Before
	public void setup() {
		filter = new Saml2WebSsoAuthenticationRequestFilter(repository);
		request = new MockHttpServletRequest();
		response = new MockHttpServletResponse();
		request.setPathInfo("/saml2/authenticate/registration-id");

		filterChain = new MockFilterChain();
	}

	@Test
	public void createSamlRequestRedirectUrlAndReturnUrlWithoutRelayState() throws ServletException, IOException {
		RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistration
				.withRegistrationId("registration-id")
				.remoteIdpEntityId("idp-entity-id")
				.idpWebSsoUrl("sso-url")
				.assertionConsumerServiceUrlTemplate("template")
				.credentials(c -> c.add(signingCredential()))
				.build();

		when(repository.findByRegistrationId("registration-id"))
				.thenReturn(relyingPartyRegistration);

		filter.doFilterInternal(request, response, filterChain);

		Assert.assertFalse(response.getHeader("Location").contains("RelayState="));
	}

	@Test
	public void createSamlRequestRedirectUrlAndReturnUrlWithRelayState() throws ServletException, IOException {
		RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistration
				.withRegistrationId("registration-id")
				.remoteIdpEntityId("idp-entity-id")
				.idpWebSsoUrl("sso-url")
				.assertionConsumerServiceUrlTemplate("template")
				.credentials(c -> c.add(signingCredential()))
				.build();

		when(repository.findByRegistrationId("registration-id"))
				.thenReturn(relyingPartyRegistration);

		request.setParameter("RelayState", "my-relay-state");

		filter.doFilterInternal(request, response, filterChain);

		Assert.assertTrue(response.getHeader("Location").contains("RelayState=my-relay-state"));
	}
}
