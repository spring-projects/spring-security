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

package org.springframework.security.saml2.provider.service.servlet.filter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.servlet.ServletException;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.web.util.UriUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.saml2.provider.service.servlet.filter.TestSaml2SigningCredentials.signingCredential;

public class Saml2WebSsoAuthenticationRequestFilterTests {

	private static final String IDP_SSO_URL = "https://sso-url.example.com/IDP/SSO";
	private Saml2WebSsoAuthenticationRequestFilter filter;
	private RelyingPartyRegistrationRepository repository = mock(RelyingPartyRegistrationRepository.class);
	private MockHttpServletRequest request;
	private MockHttpServletResponse response;
	private MockFilterChain filterChain;
	private RelyingPartyRegistration.Builder rpBuilder;

	@Before
	public void setup() {
		filter = new Saml2WebSsoAuthenticationRequestFilter(repository);
		request = new MockHttpServletRequest();
		response = new MockHttpServletResponse();
		request.setPathInfo("/saml2/authenticate/registration-id");

		filterChain = new MockFilterChain();

		rpBuilder = RelyingPartyRegistration
				.withRegistrationId("registration-id")
				.remoteIdpEntityId("idp-entity-id")
				.idpWebSsoUrl(IDP_SSO_URL)
				.assertionConsumerServiceUrlTemplate("template")
				.credentials(c -> c.add(signingCredential()));
	}

	@Test
	public void doFilterWhenNoRelayStateThenRedirectDoesNotContainParameter() throws ServletException, IOException {
		when(repository.findByRegistrationId("registration-id")).thenReturn(rpBuilder.build());
		filter.doFilterInternal(request, response, filterChain);
		assertThat(response.getHeader("Location"))
				.doesNotContain("RelayState=")
				.startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenRelayStateThenRedirectDoesContainParameter() throws ServletException, IOException {
		when(repository.findByRegistrationId("registration-id")).thenReturn(rpBuilder.build());
		request.setParameter("RelayState", "my-relay-state");
		filter.doFilterInternal(request, response, filterChain);
		assertThat(response.getHeader("Location"))
				.contains("RelayState=my-relay-state")
				.startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenRelayStateThatRequiresEncodingThenRedirectDoesContainsEncodedParameter() throws Exception {
		when(repository.findByRegistrationId("registration-id")).thenReturn(rpBuilder.build());
		final String relayStateValue = "https://my-relay-state.example.com?with=param&other=param";
		final String relayStateEncoded = UriUtils.encode(relayStateValue, StandardCharsets.ISO_8859_1);
		request.setParameter("RelayState", relayStateValue);
		filter.doFilterInternal(request, response, filterChain);
		assertThat(response.getHeader("Location"))
				.contains("RelayState="+relayStateEncoded)
				.startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenSimpleSignatureSpecifiedThenSignatureParametersAreInTheRedirectURL() throws Exception {
		when(repository.findByRegistrationId("registration-id")).thenReturn(
				rpBuilder
						.build()
		);
		final String relayStateValue = "https://my-relay-state.example.com?with=param&other=param";
		final String relayStateEncoded = UriUtils.encode(relayStateValue, StandardCharsets.ISO_8859_1);
		request.setParameter("RelayState", relayStateValue);
		filter.doFilterInternal(request, response, filterChain);
		assertThat(response.getHeader("Location"))
				.contains("RelayState="+relayStateEncoded)
				.contains("SigAlg=")
				.contains("Signature=")
				.startsWith(IDP_SSO_URL);
	}

}
