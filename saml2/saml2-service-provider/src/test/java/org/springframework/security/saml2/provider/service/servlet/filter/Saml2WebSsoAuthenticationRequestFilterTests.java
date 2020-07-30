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
import org.springframework.security.saml2.credentials.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.TestSaml2AuthenticationRequestContexts;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestContextResolver;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

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
		this.filter = new Saml2WebSsoAuthenticationRequestFilter(this.repository);
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.request.setPathInfo("/saml2/authenticate/registration-id");

		this.filterChain = new MockFilterChain();

		this.rpBuilder = RelyingPartyRegistration.withRegistrationId("registration-id")
				.providerDetails((c) -> c.entityId("idp-entity-id")).providerDetails((c) -> c.webSsoUrl(IDP_SSO_URL))
				.assertionConsumerServiceUrlTemplate("template")
				.credentials((c) -> c.add(TestSaml2X509Credentials.assertingPartyPrivateCredential()));
	}

	@Test
	public void doFilterWhenNoRelayStateThenRedirectDoesNotContainParameter() throws ServletException, IOException {
		given(this.repository.findByRegistrationId("registration-id")).willReturn(this.rpBuilder.build());
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getHeader("Location")).doesNotContain("RelayState=").startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenRelayStateThenRedirectDoesContainParameter() throws ServletException, IOException {
		given(this.repository.findByRegistrationId("registration-id")).willReturn(this.rpBuilder.build());
		this.request.setParameter("RelayState", "my-relay-state");
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getHeader("Location")).contains("RelayState=my-relay-state").startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenRelayStateThatRequiresEncodingThenRedirectDoesContainsEncodedParameter() throws Exception {
		given(this.repository.findByRegistrationId("registration-id")).willReturn(this.rpBuilder.build());
		final String relayStateValue = "https://my-relay-state.example.com?with=param&other=param";
		final String relayStateEncoded = UriUtils.encode(relayStateValue, StandardCharsets.ISO_8859_1);
		this.request.setParameter("RelayState", relayStateValue);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getHeader("Location")).contains("RelayState=" + relayStateEncoded)
				.startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenSimpleSignatureSpecifiedThenSignatureParametersAreInTheRedirectURL() throws Exception {
		given(this.repository.findByRegistrationId("registration-id")).willReturn(this.rpBuilder.build());
		final String relayStateValue = "https://my-relay-state.example.com?with=param&other=param";
		final String relayStateEncoded = UriUtils.encode(relayStateValue, StandardCharsets.ISO_8859_1);
		this.request.setParameter("RelayState", relayStateValue);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getHeader("Location")).contains("RelayState=" + relayStateEncoded).contains("SigAlg=")
				.contains("Signature=").startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenSignatureIsDisabledThenSignatureParametersAreNotInTheRedirectURL() throws Exception {
		given(this.repository.findByRegistrationId("registration-id"))
				.willReturn(this.rpBuilder.providerDetails((c) -> c.signAuthNRequest(false)).build());
		final String relayStateValue = "https://my-relay-state.example.com?with=param&other=param";
		final String relayStateEncoded = UriUtils.encode(relayStateValue, StandardCharsets.ISO_8859_1);
		this.request.setParameter("RelayState", relayStateValue);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getHeader("Location")).contains("RelayState=" + relayStateEncoded)
				.doesNotContain("SigAlg=").doesNotContain("Signature=").startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenPostFormDataIsPresent() throws Exception {
		given(this.repository.findByRegistrationId("registration-id"))
				.willReturn(this.rpBuilder.providerDetails((c) -> c.binding(Saml2MessageBinding.POST)).build());
		final String relayStateValue = "https://my-relay-state.example.com?with=param&other=param&javascript{alert('1');}";
		final String relayStateEncoded = HtmlUtils.htmlEscape(relayStateValue);
		this.request.setParameter("RelayState", relayStateValue);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getHeader("Location")).isNull();
		assertThat(this.response.getContentAsString())
				.contains("<form action=\"https://sso-url.example.com/IDP/SSO\" method=\"post\">")
				.contains("<input type=\"hidden\" name=\"SAMLRequest\"")
				.contains("value=\"" + relayStateEncoded + "\"");
	}

	@Test
	public void doFilterWhenSetAuthenticationRequestFactoryThenUses() throws Exception {
		RelyingPartyRegistration relyingParty = this.rpBuilder
				.providerDetails((c) -> c.binding(Saml2MessageBinding.POST)).build();
		Saml2PostAuthenticationRequest authenticationRequest = mock(Saml2PostAuthenticationRequest.class);
		given(authenticationRequest.getAuthenticationRequestUri()).willReturn("uri");
		given(authenticationRequest.getRelayState()).willReturn("relay");
		given(authenticationRequest.getSamlRequest()).willReturn("saml");
		given(this.repository.findByRegistrationId("registration-id")).willReturn(relyingParty);
		given(this.factory.createPostAuthenticationRequest(any())).willReturn(authenticationRequest);

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
		RelyingPartyRegistration relyingParty = this.rpBuilder
				.providerDetails((c) -> c.binding(Saml2MessageBinding.POST)).build();
		Saml2PostAuthenticationRequest authenticationRequest = mock(Saml2PostAuthenticationRequest.class);
		given(authenticationRequest.getAuthenticationRequestUri()).willReturn("uri");
		given(authenticationRequest.getRelayState()).willReturn("relay");
		given(authenticationRequest.getSamlRequest()).willReturn("saml");
		given(this.resolver.resolve(this.request)).willReturn(TestSaml2AuthenticationRequestContexts
				.authenticationRequestContext().relyingPartyRegistration(relyingParty).build());
		given(this.factory.createPostAuthenticationRequest(any())).willReturn(authenticationRequest);

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
		filter.setRedirectMatcher((request) -> false);
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
