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
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2PostAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.TestSaml2AuthenticationRequestContexts;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestContextResolver;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
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
		this.filter = new Saml2WebSsoAuthenticationRequestFilter(this.resolver, this.factory);
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
		Saml2AuthenticationRequestContext context = authenticationRequestContext().relayState(null).build();
		Saml2RedirectAuthenticationRequest request = redirectAuthenticationRequest(context).build();
		given(this.resolver.resolve(any())).willReturn(context);
		given(this.factory.createRedirectAuthenticationRequest(any())).willReturn(request);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getHeader("Location")).doesNotContain("RelayState=").startsWith(IDP_SSO_URL);
	}

	private static Saml2AuthenticationRequestContext.Builder authenticationRequestContext() {
		return TestSaml2AuthenticationRequestContexts.authenticationRequestContext();
	}

	private static Saml2RedirectAuthenticationRequest.Builder redirectAuthenticationRequest(
			Saml2AuthenticationRequestContext context) {
		return Saml2RedirectAuthenticationRequest.withAuthenticationRequestContext(context).samlRequest("request")
				.authenticationRequestUri(IDP_SSO_URL);
	}

	private static Saml2PostAuthenticationRequest.Builder postAuthenticationRequest(
			Saml2AuthenticationRequestContext context) {
		return Saml2PostAuthenticationRequest.withAuthenticationRequestContext(context).samlRequest("request")
				.authenticationRequestUri(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenRelayStateThenRedirectDoesContainParameter() throws ServletException, IOException {
		Saml2AuthenticationRequestContext context = authenticationRequestContext().build();
		Saml2RedirectAuthenticationRequest request = redirectAuthenticationRequest(context).build();
		given(this.resolver.resolve(any())).willReturn(context);
		given(this.factory.createRedirectAuthenticationRequest(any())).willReturn(request);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getHeader("Location")).contains("RelayState=relayState").startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenRelayStateThatRequiresEncodingThenRedirectDoesContainsEncodedParameter() throws Exception {
		String relayStateValue = "https://my-relay-state.example.com?with=param&other=param";
		String relayStateEncoded = UriUtils.encode(relayStateValue, StandardCharsets.ISO_8859_1);
		Saml2AuthenticationRequestContext context = authenticationRequestContext().relayState(relayStateValue).build();
		Saml2RedirectAuthenticationRequest request = redirectAuthenticationRequest(context).build();
		given(this.resolver.resolve(any())).willReturn(context);
		given(this.factory.createRedirectAuthenticationRequest(any())).willReturn(request);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getHeader("Location")).contains("RelayState=" + relayStateEncoded)
				.startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenSimpleSignatureSpecifiedThenSignatureParametersAreInTheRedirectURL() throws Exception {
		Saml2AuthenticationRequestContext context = authenticationRequestContext().build();
		Saml2RedirectAuthenticationRequest request = redirectAuthenticationRequest(context).sigAlg("sigalg")
				.signature("signature").build();
		given(this.resolver.resolve(any())).willReturn(context);
		given(this.factory.createRedirectAuthenticationRequest(any())).willReturn(request);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getHeader("Location")).contains("SigAlg=").contains("Signature=")
				.startsWith(IDP_SSO_URL);
	}

	@Test
	public void doFilterWhenSignatureIsDisabledThenSignatureParametersAreNotInTheRedirectURL() throws Exception {
		Saml2AuthenticationRequestContext context = authenticationRequestContext().build();
		Saml2RedirectAuthenticationRequest request = redirectAuthenticationRequest(context).build();
		given(this.resolver.resolve(any())).willReturn(context);
		given(this.factory.createRedirectAuthenticationRequest(any())).willReturn(request);
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
		Saml2AuthenticationRequestContext context = authenticationRequestContext().relayState(relayStateValue)
				.relyingPartyRegistration(registration).build();
		Saml2PostAuthenticationRequest request = postAuthenticationRequest(context).build();
		given(this.resolver.resolve(any())).willReturn(context);
		given(this.factory.createPostAuthenticationRequest(any())).willReturn(request);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		assertThat(this.response.getHeader("Location")).isNull();
		assertThat(this.response.getContentAsString())
				.contains("<form action=\"https://sso-url.example.com/IDP/SSO\" method=\"post\">")
				.contains("<input type=\"hidden\" name=\"SAMLRequest\"")
				.contains("value=\"" + relayStateEncoded + "\"");
	}

	@Test
	public void doFilterWhenSetAuthenticationRequestFactoryThenUses() throws Exception {
		Saml2AuthenticationRequestContext context = authenticationRequestContext().build();
		Saml2RedirectAuthenticationRequest authenticationRequest = redirectAuthenticationRequest(context).build();
		Saml2AuthenticationRequestFactory factory = mock(Saml2AuthenticationRequestFactory.class);
		given(this.resolver.resolve(any())).willReturn(context);
		given(factory.createRedirectAuthenticationRequest(any())).willReturn(authenticationRequest);
		this.filter.setAuthenticationRequestFactory(factory);
		this.filter.doFilterInternal(this.request, this.response, this.filterChain);
		verify(factory).createRedirectAuthenticationRequest(any());
	}

	@Test
	public void setRequestMatcherWhenNullThenException() {
		Saml2WebSsoAuthenticationRequestFilter filter = new Saml2WebSsoAuthenticationRequestFilter(this.resolver,
				this.factory);
		assertThatIllegalArgumentException().isThrownBy(() -> filter.setRedirectMatcher(null));
	}

	@Test
	public void setAuthenticationRequestFactoryWhenNullThenException() {
		Saml2WebSsoAuthenticationRequestFilter filter = new Saml2WebSsoAuthenticationRequestFilter(this.resolver,
				this.factory);
		assertThatIllegalArgumentException().isThrownBy(() -> filter.setAuthenticationRequestFactory(null));
	}

	@Test
	public void doFilterWhenRequestMatcherFailsThenSkipsFilter() throws Exception {
		Saml2WebSsoAuthenticationRequestFilter filter = new Saml2WebSsoAuthenticationRequestFilter(this.resolver,
				this.factory);
		filter.setRedirectMatcher((request) -> false);
		filter.doFilter(this.request, this.response, this.filterChain);
		verifyNoInteractions(this.resolver, this.factory);
	}

	@Test
	public void doFilterWhenRelyingPartyRegistrationNotFoundThenUnauthorized() throws Exception {
		Saml2WebSsoAuthenticationRequestFilter filter = new Saml2WebSsoAuthenticationRequestFilter(this.resolver,
				this.factory);
		filter.doFilter(this.request, this.response, this.filterChain);
		assertThat(this.response.getStatus()).isEqualTo(401);
	}

}
