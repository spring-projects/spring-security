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

package org.springframework.security.saml2.provider.service.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.saml2.credentials.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class Saml2WebSsoAuthenticationRequestFilterTests {

	private static final String IDP_SSO_URL = "https://sso-url.example.com/IDP/SSO";

	private Saml2WebSsoAuthenticationRequestFilter filter;

	private RelyingPartyRegistrationRepository repository = mock(RelyingPartyRegistrationRepository.class);

	private Saml2AuthenticationRequestResolver authenticationRequestResolver = mock(
			Saml2AuthenticationRequestResolver.class);

	private Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository = mock(
			Saml2AuthenticationRequestRepository.class);

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private MockFilterChain filterChain;

	private RelyingPartyRegistration.Builder rpBuilder;

	@BeforeEach
	public void setup() {
		this.filter = new Saml2WebSsoAuthenticationRequestFilter(this.authenticationRequestResolver);
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.request.setPathInfo("/saml2/authenticate/registration-id");
		this.filterChain = new MockFilterChain() {
			@Override
			public void doFilter(ServletRequest request, ServletResponse response) {
				((HttpServletResponse) response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			}
		};
		this.rpBuilder = RelyingPartyRegistration.withRegistrationId("registration-id")
				.assertingPartyDetails((c) -> c.entityId("idp-entity-id"))
				.assertingPartyDetails((c) -> c.singleSignOnServiceLocation(IDP_SSO_URL))
				.assertionConsumerServiceLocation("template")
				.signingX509Credentials((c) -> c.add(TestSaml2X509Credentials.assertingPartyPrivateCredential()))
				.decryptionX509Credentials((c) -> c.add(TestSaml2X509Credentials.assertingPartyPrivateCredential()));
		this.filter.setAuthenticationRequestRepository(this.authenticationRequestRepository);
	}

	@Test
	public void doFilterWhenNoRelayStateThenRedirectDoesNotContainParameter() throws ServletException, IOException {
		Saml2RedirectAuthenticationRequest request = redirectAuthenticationRequest().build();
		given(this.authenticationRequestResolver.resolve(any())).willReturn(request);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getHeader("Location")).doesNotContain("RelayState=").startsWith(IDP_SSO_URL);
	}

	private static Saml2RedirectAuthenticationRequest.Builder redirectAuthenticationRequest() {
		return Saml2RedirectAuthenticationRequest
				.withRelyingPartyRegistration(TestRelyingPartyRegistrations.relyingPartyRegistration().build())
				.samlRequest("request").authenticationRequestUri(IDP_SSO_URL);
	}

	private static Saml2RedirectAuthenticationRequest.Builder redirectAuthenticationRequest(
			RelyingPartyRegistration registration) {
		return Saml2RedirectAuthenticationRequest.withRelyingPartyRegistration(registration).samlRequest("request")
				.authenticationRequestUri(IDP_SSO_URL);
	}

	private static Saml2PostAuthenticationRequest.Builder postAuthenticationRequest() {
		return Saml2PostAuthenticationRequest
				.withRelyingPartyRegistration(TestRelyingPartyRegistrations.relyingPartyRegistration().build())
				.samlRequest("request").authenticationRequestUri(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenRelayStateThenRedirectDoesContainParameter() throws ServletException, IOException {
		Saml2RedirectAuthenticationRequest request = redirectAuthenticationRequest().relayState("relayState").build();
		given(this.authenticationRequestResolver.resolve(any())).willReturn(request);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getHeader("Location")).contains("RelayState=relayState").startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenRelayStateThatRequiresEncodingThenRedirectDoesContainsEncodedParameter() throws Exception {
		String relayStateValue = "https://my-relay-state.example.com?with=param&other=param";
		String relayStateEncoded = UriUtils.encode(relayStateValue, StandardCharsets.ISO_8859_1);
		Saml2RedirectAuthenticationRequest request = redirectAuthenticationRequest().relayState(relayStateValue)
				.build();
		given(this.authenticationRequestResolver.resolve(any())).willReturn(request);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getHeader("Location")).contains("RelayState=" + relayStateEncoded)
				.startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenSimpleSignatureSpecifiedThenSignatureParametersAreInTheRedirectURL() throws Exception {
		Saml2RedirectAuthenticationRequest request = redirectAuthenticationRequest().sigAlg("sigalg")
				.signature("signature").build();
		given(this.authenticationRequestResolver.resolve(any())).willReturn(request);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getHeader("Location")).contains("SigAlg=").contains("Signature=")
				.startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenSignatureIsDisabledThenSignatureParametersAreNotInTheRedirectURL() throws Exception {
		Saml2RedirectAuthenticationRequest request = redirectAuthenticationRequest().build();
		given(this.authenticationRequestResolver.resolve(any())).willReturn(request);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getHeader("Location")).doesNotContain("SigAlg=").doesNotContain("Signature=")
				.startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenPostFormDataIsPresent() throws Exception {
		String relayStateValue = "https://my-relay-state.example.com?with=param&other=param&javascript{alert('1');}";
		String relayStateEncoded = HtmlUtils.htmlEscape(relayStateValue);
		RelyingPartyRegistration registration = this.rpBuilder
				.assertingPartyDetails((asserting) -> asserting.singleSignOnServiceBinding(Saml2MessageBinding.POST))
				.build();
		Saml2PostAuthenticationRequest request = Saml2PostAuthenticationRequest
				.withRelyingPartyRegistration(registration).samlRequest("request").relayState(relayStateValue).build();
		given(this.authenticationRequestResolver.resolve(any())).willReturn(request);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getHeader("Location")).isNull();
		assertThat(this.response.getContentAsString()).contains(
				"<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'sha256-t+jmhLjs1ocvgaHBJsFcgznRk68d37TLtbI3NE9h7EU='\">")
				.contains("<script>window.onload = () => document.forms[0].submit();</script>")
				.contains("<form action=\"https://sso-url.example.com/IDP/SSO\" method=\"post\">")
				.contains("<input type=\"hidden\" name=\"SAMLRequest\"")
				.contains("value=\"" + relayStateEncoded + "\"");
	}

	@Test
	public void doFilterWhenRelyingPartyRegistrationNotFoundThenUnauthorized() throws Exception {
		Saml2WebSsoAuthenticationRequestFilter filter = new Saml2WebSsoAuthenticationRequestFilter(
				this.authenticationRequestResolver);
		filter.doFilter(this.request, this.response, this.filterChain);
		assertThat(this.response.getStatus()).isEqualTo(401);
	}

	@Test
	public void setAuthenticationRequestRepositoryWhenNullThenException() {
		Saml2WebSsoAuthenticationRequestFilter filter = new Saml2WebSsoAuthenticationRequestFilter(
				this.authenticationRequestResolver);
		assertThatIllegalArgumentException().isThrownBy(() -> filter.setAuthenticationRequestRepository(null));
	}

	@Test
	public void doFilterWhenRedirectThenSaveRedirectRequest() throws ServletException, IOException {
		Saml2RedirectAuthenticationRequest request = redirectAuthenticationRequest().build();
		given(this.authenticationRequestResolver.resolve(any())).willReturn(request);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		verify(this.authenticationRequestRepository).saveAuthenticationRequest(
				any(Saml2RedirectAuthenticationRequest.class), eq(this.request), eq(this.response));
	}

	@Test
	public void doFilterWhenPostThenSaveRedirectRequest() throws ServletException, IOException {
		RelyingPartyRegistration registration = this.rpBuilder
				.assertingPartyDetails((asserting) -> asserting.singleSignOnServiceBinding(Saml2MessageBinding.POST))
				.build();
		Saml2PostAuthenticationRequest request = Saml2PostAuthenticationRequest
				.withRelyingPartyRegistration(registration).samlRequest("request").build();
		given(this.authenticationRequestResolver.resolve(any())).willReturn(request);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		verify(this.authenticationRequestRepository).saveAuthenticationRequest(
				any(Saml2PostAuthenticationRequest.class), eq(this.request), eq(this.response));
	}

	@Test
	public void doFilterWhenCustomAuthenticationRequestResolverThenUses() throws Exception {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.relyingPartyRegistration().build();
		Saml2RedirectAuthenticationRequest authenticationRequest = redirectAuthenticationRequest(registration).build();
		Saml2WebSsoAuthenticationRequestFilter filter = new Saml2WebSsoAuthenticationRequestFilter(
				this.authenticationRequestResolver);
		given(this.authenticationRequestResolver.resolve(any())).willReturn(authenticationRequest);
		filter.doFilterInternal(this.request, this.response, this.filterChain);
		verify(this.authenticationRequestResolver).resolve(any());
	}

}
