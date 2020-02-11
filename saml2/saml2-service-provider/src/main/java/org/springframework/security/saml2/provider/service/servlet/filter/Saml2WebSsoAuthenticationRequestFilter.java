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

import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2RedirectAuthenticationRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher.MatchResult;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static org.springframework.util.StringUtils.hasText;

/**
 * @since 5.2
 */
public class Saml2WebSsoAuthenticationRequestFilter extends OncePerRequestFilter {

	private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
	private RequestMatcher redirectMatcher = new AntPathRequestMatcher("/saml2/authenticate/{registrationId}");
	private Saml2AuthenticationRequestFactory authenticationRequestFactory = new OpenSamlAuthenticationRequestFactory();

	public Saml2WebSsoAuthenticationRequestFilter(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
		Assert.notNull(relyingPartyRegistrationRepository, "relyingPartyRegistrationRepository cannot be null");
		this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
	}

	public void setAuthenticationRequestFactory(Saml2AuthenticationRequestFactory authenticationRequestFactory) {
		Assert.notNull(authenticationRequestFactory, "authenticationRequestFactory cannot be null");
		this.authenticationRequestFactory = authenticationRequestFactory;
	}

	public void setRedirectMatcher(RequestMatcher redirectMatcher) {
		Assert.notNull(redirectMatcher, "redirectMatcher cannot be null");
		this.redirectMatcher = redirectMatcher;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		MatchResult matcher = this.redirectMatcher.matcher(request);
		if (!matcher.isMatch()) {
			filterChain.doFilter(request, response);
			return;
		}

		String registrationId = matcher.getVariables().get("registrationId");
		sendRedirect(request, response, registrationId);
	}

	private void sendRedirect(HttpServletRequest request, HttpServletResponse response, String registrationId)
			throws IOException {
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(format("Creating SAML2 SP Authentication Request for IDP[%s]", registrationId));
		}
		RelyingPartyRegistration relyingParty = this.relyingPartyRegistrationRepository.findByRegistrationId(registrationId);
		String redirectUrl = createSamlRequestRedirectUrl(request, relyingParty);
		response.sendRedirect(redirectUrl);
	}

	private String createSamlRequestRedirectUrl(HttpServletRequest request, RelyingPartyRegistration relyingParty) {
		Saml2AuthenticationRequestContext authnRequest = createRedirectAuthenticationRequestContext(relyingParty, request);
		Saml2RedirectAuthenticationRequest authNData =
				this.authenticationRequestFactory.createRedirectAuthenticationRequest(authnRequest);
		UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUriString(authNData.getAuthenticationRequestUri());
		addParameter("SAMLRequest", authNData.getSamlRequest(), uriBuilder);
		addParameter("RelayState", authNData.getRelayState(), uriBuilder);
		addParameter("SigAlg", authNData.getSigAlg(), uriBuilder);
		addParameter("Signature", authNData.getSignature(), uriBuilder);
		return uriBuilder
				.build(true)
				.toUriString();
	}

	private void addParameter(String name, String value, UriComponentsBuilder builder) {
		Assert.hasText(name, "name cannot be empty or null");
		if (hasText(value)) {
			builder.queryParam(
					UriUtils.encode(name, ISO_8859_1),
					UriUtils.encode(value, ISO_8859_1)
			);
		}
	}

	private Saml2AuthenticationRequestContext createRedirectAuthenticationRequestContext(
			RelyingPartyRegistration relyingParty,
			HttpServletRequest request) {
		String localSpEntityId = Saml2ServletUtils.getServiceProviderEntityId(relyingParty, request);
		return Saml2AuthenticationRequestContext
				.builder()
				.issuer(localSpEntityId)
				.relyingPartyRegistration(relyingParty)
				.assertionConsumerServiceUrl(
						Saml2ServletUtils.resolveUrlTemplate(
								relyingParty.getAssertionConsumerServiceUrlTemplate(),
								Saml2ServletUtils.getApplicationUri(request),
								relyingParty.getRemoteIdpEntityId(),
								relyingParty.getRegistrationId()
						)
				)
				.relayState(request.getParameter("RelayState"))
				.build()
				;
	}
}
