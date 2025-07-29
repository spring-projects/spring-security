/*
 * Copyright 2004-present the original author or authors.
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

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpMethod;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationConverter} that generates a {@link Saml2AuthenticationToken}
 * appropriate for authenticated a SAML 2.0 Assertion against an
 * {@link org.springframework.security.authentication.AuthenticationManager}.
 *
 * @author Josh Cummings
 * @since 5.4
 */
public final class Saml2AuthenticationTokenConverter implements AuthenticationConverter {

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	private Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository;

	/**
	 * Constructs a {@link Saml2AuthenticationTokenConverter} given a strategy for
	 * resolving {@link RelyingPartyRegistration}s
	 * @param relyingPartyRegistrationResolver the strategy for resolving
	 * {@link RelyingPartyRegistration}s
	 */
	public Saml2AuthenticationTokenConverter(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		Assert.notNull(relyingPartyRegistrationResolver, "relyingPartyRegistrationResolver cannot be null");
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
		this.authenticationRequestRepository = new HttpSessionSaml2AuthenticationRequestRepository();
	}

	@Override
	public Saml2AuthenticationToken convert(HttpServletRequest request) {
		AbstractSaml2AuthenticationRequest authenticationRequest = this.authenticationRequestRepository
			.loadAuthenticationRequest(request);
		String relyingPartyRegistrationId = (authenticationRequest != null)
				? authenticationRequest.getRelyingPartyRegistrationId() : null;
		RelyingPartyRegistration relyingPartyRegistration = this.relyingPartyRegistrationResolver.resolve(request,
				relyingPartyRegistrationId);
		if (relyingPartyRegistration == null) {
			return null;
		}
		String saml2Response = decode(request);
		if (saml2Response == null) {
			return null;
		}
		return new Saml2AuthenticationToken(relyingPartyRegistration, saml2Response, authenticationRequest);
	}

	/**
	 * Use the given {@link Saml2AuthenticationRequestRepository} to load authentication
	 * request.
	 * @param authenticationRequestRepository the
	 * {@link Saml2AuthenticationRequestRepository} to use
	 * @since 5.6
	 */
	public void setAuthenticationRequestRepository(
			Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository) {
		Assert.notNull(authenticationRequestRepository, "authenticationRequestRepository cannot be null");
		this.authenticationRequestRepository = authenticationRequestRepository;
	}

	private String decode(HttpServletRequest request) {
		String encoded = request.getParameter(Saml2ParameterNames.SAML_RESPONSE);
		if (encoded == null) {
			return null;
		}
		try {
			return Saml2Utils.withEncoded(encoded)
				.requireBase64(true)
				.inflate(HttpMethod.GET.matches(request.getMethod()))
				.decode();
		}
		catch (Exception ex) {
			throw new Saml2AuthenticationException(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, ex.getMessage()),
					ex);
		}
	}

}
