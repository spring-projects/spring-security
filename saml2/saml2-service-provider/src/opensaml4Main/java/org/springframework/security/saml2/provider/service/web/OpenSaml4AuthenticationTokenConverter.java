/*
 * Copyright 2002-2023 the original author or authors.
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

import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationConverter} that generates a {@link Saml2AuthenticationToken}
 * appropriate for authenticated a SAML 2.0 Assertion against an
 * {@link org.springframework.security.authentication.AuthenticationManager}.
 *
 * @author Josh Cummings
 * @since 6.1
 */
public final class OpenSaml4AuthenticationTokenConverter implements AuthenticationConverter {

	private final BaseOpenSamlAuthenticationTokenConverter delegate;

	/**
	 * Constructs a {@link OpenSaml4AuthenticationTokenConverter} given a repository for
	 * {@link RelyingPartyRegistration}s
	 * @param registrations the repository for {@link RelyingPartyRegistration}s
	 * {@link RelyingPartyRegistration}s
	 */
	public OpenSaml4AuthenticationTokenConverter(RelyingPartyRegistrationRepository registrations) {
		Assert.notNull(registrations, "relyingPartyRegistrationRepository cannot be null");
		this.delegate = new BaseOpenSamlAuthenticationTokenConverter(registrations, new OpenSaml4Template());
	}

	/**
	 * Resolve an authentication request from the given {@link HttpServletRequest}.
	 *
	 * <p>
	 * First uses the configured {@link RequestMatcher} to deduce whether an
	 * authentication request is being made and optionally for which
	 * {@code registrationId}.
	 *
	 * <p>
	 * If there is an associated {@code <saml2:AuthnRequest>}, then the
	 * {@code registrationId} is looked up and used.
	 *
	 * <p>
	 * If a {@code registrationId} is found in the request, then it is looked up and used.
	 * In that case, if none is found a {@link Saml2AuthenticationException} is thrown.
	 *
	 * <p>
	 * Finally, if no {@code registrationId} is found in the request, then the code
	 * attempts to resolve the {@link RelyingPartyRegistration} from the SAML Response's
	 * Issuer.
	 * @param request the HTTP request
	 * @return the {@link Saml2AuthenticationToken} authentication request
	 * @throws Saml2AuthenticationException if the {@link RequestMatcher} specifies a
	 * non-existent {@code registrationId}
	 */
	@Override
	public Saml2AuthenticationToken convert(HttpServletRequest request) {
		return this.delegate.convert(request);
	}

	/**
	 * Use the given {@link Saml2AuthenticationRequestRepository} to load authentication
	 * request.
	 * @param authenticationRequestRepository the
	 * {@link Saml2AuthenticationRequestRepository} to use
	 */
	public void setAuthenticationRequestRepository(
			Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository) {
		Assert.notNull(authenticationRequestRepository, "authenticationRequestRepository cannot be null");
		this.delegate.setAuthenticationRequestRepository(authenticationRequestRepository);
	}

	/**
	 * Use the given {@link RequestMatcher} to match the request.
	 * @param requestMatcher the {@link RequestMatcher} to use
	 */
	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.delegate.setRequestMatcher(requestMatcher);
	}

}
