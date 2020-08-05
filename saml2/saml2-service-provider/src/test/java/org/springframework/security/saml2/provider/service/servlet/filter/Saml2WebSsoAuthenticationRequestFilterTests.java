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
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestContextResolver;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.saml2.credentials.TestSaml2X509Credentials.assertingPartyPrivateCredential;
import static org.springframework.security.saml2.provider.service.authentication.TestSaml2AuthenticationRequestContexts.authenticationRequestContext;
import static org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding.POST;

public class Saml2WebSsoAuthenticationRequestFilterTests {

	private static final String IDP_SSO_URL = "https://sso-url.example.com/IDP/SSO";

	private Saml2WebSsoAuthenticationRequestFilter filter;

	private RelyingPartyRegistrationRepository repository = mock(RelyingPartyRegistrationRepository.class);

	private Saml2AuthenticationRequestFactory factory = mock(Saml2AuthenticationRequestFactory.class);

	private Saml2AuthenticationRequestContextResolver resolver = mock(Saml2AuthenticationRequestContextResolver.class);

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

		rpBuilder = RelyingPartyRegistration.withRegistrationId("registration-id")
				.providerDetails(c -> c.entityId("idp-entity-id")).providerDetails(c -> c.webSsoUrl(IDP_SSO_URL))
				.assertionConsumerServiceUrlTemplate("template")
				.credentials(c -> c.add(assertingPartyPrivateCredential()));
	}

	@Test
	public void doFilterWhenNoRelayStateThenRedirectDoesNotContainParameter() throws ServletException, IOException {
		when(repository.findByRegistrationId("registration-id")).thenReturn(rpBuilder.build());
		filter.doFilterInternal(request, response, filterChain);
		assertThat(response.getHeader("Location")).doesNotContain("RelayState=").startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenRelayStateThenRedirectDoesContainParameter() throws ServletException, IOException {
		when(repository.findByRegistrationId("registration-id")).thenReturn(rpBuilder.build());
		request.setParameter("RelayState", "my-relay-state");
		filter.doFilterInternal(request, response, filterChain);
		assertThat(response.getHeader("Location")).contains("RelayState=my-relay-state").startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenRelayStateThatRequiresEncodingThenRedirectDoesContainsEncodedParameter() throws Exception {
		when(repository.findByRegistrationId("registration-id")).thenReturn(rpBuilder.build());
		final String relayStateValue = "https://my-relay-state.example.com?with=param&other=param";
		final String relayStateEncoded = UriUtils.encode(relayStateValue, StandardCharsets.ISO_8859_1);
		request.setParameter("RelayState", relayStateValue);
		filter.doFilterInternal(request, response, filterChain);
		assertThat(response.getHeader("Location")).contains("RelayState=" + relayStateEncoded).startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenSimpleSignatureSpecifiedThenSignatureParametersAreInTheRedirectURL() throws Exception {
		when(repository.findByRegistrationId("registration-id")).thenReturn(rpBuilder.build());
		final String relayStateValue = "https://my-relay-state.example.com?with=param&other=param";
		final String relayStateEncoded = UriUtils.encode(relayStateValue, StandardCharsets.ISO_8859_1);
		request.setParameter("RelayState", relayStateValue);
		filter.doFilterInternal(request, response, filterChain);
		assertThat(response.getHeader("Location")).contains("RelayState=" + relayStateEncoded).contains("SigAlg=")
				.contains("Signature=").startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenSignatureIsDisabledThenSignatureParametersAreNotInTheRedirectURL() throws Exception {
		when(repository.findByRegistrationId("registration-id"))
				.thenReturn(rpBuilder.providerDetails(c -> c.signAuthNRequest(false)).build());
		final String relayStateValue = "https://my-relay-state.example.com?with=param&other=param";
		final String relayStateEncoded = UriUtils.encode(relayStateValue, StandardCharsets.ISO_8859_1);
		request.setParameter("RelayState", relayStateValue);
		filter.doFilterInternal(request, response, filterChain);
		assertThat(response.getHeader("Location")).contains("RelayState=" + relayStateEncoded).doesNotContain("SigAlg=")
				.doesNotContain("Signature=").startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenPostFormDataIsPresent() throws Exception {
		when(repository.findByRegistrationId("registration-id"))
				.thenReturn(rpBuilder.providerDetails(c -> c.binding(POST)).build());
		final String relayStateValue = "https://my-relay-state.example.com?with=param&other=param&javascript{alert('1');}";
		final String relayStateEncoded = HtmlUtils.htmlEscape(relayStateValue);
		request.setParameter("RelayState", relayStateValue);
		filter.doFilterInternal(request, response, filterChain);
		assertThat(response.getHeader("Location")).isNull();
		assertThat(response.getContentAsString())
				.contains("<form action=\"https://sso-url.example.com/IDP/SSO\" method=\"post\">")
				.contains("<input type=\"hidden\" name=\"SAMLRequest\"")
				.contains("value=\"" + relayStateEncoded + "\"");
	}

	@Test
	public void doFilterWhenSetAuthenticationRequestFactoryThenUses() throws Exception {
		RelyingPartyRegistration relyingParty = this.rpBuilder.providerDetails(c -> c.binding(POST)).build();
		Saml2PostAuthenticationRequest authenticationRequest = mock(Saml2PostAuthenticationRequest.class);
		when(authenticationRequest.getAuthenticationRequestUri()).thenReturn("uri");
		when(authenticationRequest.getRelayState()).thenReturn("relay");
		when(authenticationRequest.getSamlRequest()).thenReturn("saml");
		when(this.repository.findByRegistrationId("registration-id")).thenReturn(relyingParty);
		when(this.factory.createPostAuthenticationRequest(any())).thenReturn(authenticationRequest);

		Saml2WebSsoAuthenticationRequestFilter filter = new Saml2WebSsoAuthenticationRequestFilter(this.repository);
		filter.setAuthenticationRequestFactory(this.factory);
		filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getContentAsString()).contains("<form action=\"uri\" method=\"post\">")
				.contains("<input type=\"hidden\" name=\"SAMLRequest\" value=\"saml\"")
				.contains("<input type=\"hidden\" name=\"RelayState\" value=\"relay\"");
		verify(this.factory).createPostAuthenticationRequest(any());
	}

	@Test
	public void doFilterWhenCustomAuthenticationRequestFactoryThenUses() throws Exception {
		RelyingPartyRegistration relyingParty = this.rpBuilder.providerDetails(c -> c.binding(POST)).build();
		Saml2PostAuthenticationRequest authenticationRequest = mock(Saml2PostAuthenticationRequest.class);
		when(authenticationRequest.getAuthenticationRequestUri()).thenReturn("uri");
		when(authenticationRequest.getRelayState()).thenReturn("relay");
		when(authenticationRequest.getSamlRequest()).thenReturn("saml");
		when(this.resolver.resolve(this.request))
				.thenReturn(authenticationRequestContext().relyingPartyRegistration(relyingParty).build());
		when(this.factory.createPostAuthenticationRequest(any())).thenReturn(authenticationRequest);

		Saml2WebSsoAuthenticationRequestFilter filter = new Saml2WebSsoAuthenticationRequestFilter(this.resolver,
				this.factory);
		filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getContentAsString()).contains("<form action=\"uri\" method=\"post\">")
				.contains("<input type=\"hidden\" name=\"SAMLRequest\" value=\"saml\"")
				.contains("<input type=\"hidden\" name=\"RelayState\" value=\"relay\"");
		verify(this.factory).createPostAuthenticationRequest(any());
	}

	@Test
	public void setRequestMatcherWhenNullThenException() {
		Saml2WebSsoAuthenticationRequestFilter filter = new Saml2WebSsoAuthenticationRequestFilter(this.repository);
		assertThatCode(() -> filter.setRedirectMatcher(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void setAuthenticationRequestFactoryWhenNullThenException() {
		Saml2WebSsoAuthenticationRequestFilter filter = new Saml2WebSsoAuthenticationRequestFilter(this.repository);
		assertThatCode(() -> filter.setAuthenticationRequestFactory(null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void doFilterWhenRequestMatcherFailsThenSkipsFilter() throws Exception {
		Saml2WebSsoAuthenticationRequestFilter filter = new Saml2WebSsoAuthenticationRequestFilter(this.repository);
		filter.setRedirectMatcher(request -> false);
		filter.doFilter(this.request, this.response, this.filterChain);
		verifyNoInteractions(this.repository);
	}

	@Test
	public void doFilterWhenRelyingPartyRegistrationNotFoundThenUnauthorized() throws Exception {
		Saml2WebSsoAuthenticationRequestFilter filter = new Saml2WebSsoAuthenticationRequestFilter(this.repository);
		filter.doFilter(this.request, this.response, this.filterChain);
		assertThat(this.response.getStatus()).isEqualTo(401);
	}

}
