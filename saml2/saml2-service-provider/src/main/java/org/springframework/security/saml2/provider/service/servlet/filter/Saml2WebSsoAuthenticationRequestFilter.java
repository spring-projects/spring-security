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

import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher.MatchResult;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static java.lang.String.format;
import static org.springframework.security.saml2.provider.service.servlet.filter.Saml2Utils.deflate;
import static org.springframework.security.saml2.provider.service.servlet.filter.Saml2Utils.encode;

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
		Saml2AuthenticationRequest authNRequest = createAuthenticationRequest(relyingParty, request);
		String xml = this.authenticationRequestFactory.createAuthenticationRequest(authNRequest);
		String encoded = encode(deflate(xml));
		String relayState = request.getParameter("RelayState");
		String redirect = UriComponentsBuilder
				.fromUriString(relyingParty.getIdpWebSsoUrl())
				.queryParam("SAMLRequest", UriUtils.encode(encoded, StandardCharsets.ISO_8859_1))
				.queryParam("RelayState", UriUtils.encode(relayState, StandardCharsets.ISO_8859_1))
				.build(true)
				.toUriString();
		return redirect;
	}

	private Saml2AuthenticationRequest createAuthenticationRequest(RelyingPartyRegistration relyingParty, HttpServletRequest request) {
		String localSpEntityId = Saml2Utils.getServiceProviderEntityId(relyingParty, request);
		return new Saml2AuthenticationRequest(
				localSpEntityId,
				relyingParty.getIdpWebSsoUrl(),
				relyingParty.getSigningCredentials()
		);
	}

}
