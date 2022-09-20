/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.HttpSessionSaml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationRequestRepository;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.util.Assert;

/**
 * @since 5.2
 */
public class Saml2WebSsoAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	public static final String DEFAULT_FILTER_PROCESSES_URI = "/login/saml2/sso/{registrationId}";

	private final AuthenticationConverter authenticationConverter;

	private Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository = new HttpSessionSaml2AuthenticationRequestRepository();

	/**
	 * Creates a {@code Saml2WebSsoAuthenticationFilter} authentication filter that is
	 * configured to use the {@link #DEFAULT_FILTER_PROCESSES_URI} processing URL
	 * @param relyingPartyRegistrationRepository - repository of configured SAML 2
	 * entities. Required.
	 */
	public Saml2WebSsoAuthenticationFilter(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
		this(relyingPartyRegistrationRepository, DEFAULT_FILTER_PROCESSES_URI);
	}

	/**
	 * Creates a {@code Saml2WebSsoAuthenticationFilter} authentication filter
	 * @param relyingPartyRegistrationRepository - repository of configured SAML 2
	 * entities. Required.
	 * @param filterProcessesUrl the processing URL, must contain a {registrationId}
	 * variable. Required.
	 */
	public Saml2WebSsoAuthenticationFilter(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
			String filterProcessesUrl) {
		this(new Saml2AuthenticationTokenConverter(
				(RelyingPartyRegistrationResolver) new DefaultRelyingPartyRegistrationResolver(
						relyingPartyRegistrationRepository)),
				filterProcessesUrl);
		Assert.isTrue(filterProcessesUrl.contains("{registrationId}"),
				"filterProcessesUrl must contain a {registrationId} match variable");
	}

	/**
	 * Creates a {@link Saml2WebSsoAuthenticationFilter} given the provided parameters
	 * @param authenticationConverter the strategy for converting an
	 * {@link HttpServletRequest} into an {@link Authentication}
	 * @param filterProcessesUrl the processing URL
	 * @since 5.4
	 */
	public Saml2WebSsoAuthenticationFilter(AuthenticationConverter authenticationConverter, String filterProcessesUrl) {
		super(filterProcessesUrl);
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		Assert.hasText(filterProcessesUrl, "filterProcessesUrl must contain a URL pattern");
		this.authenticationConverter = authenticationConverter;
		setAllowSessionCreation(true);
		setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		return super.requiresAuthentication(request, response);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		Authentication authentication = this.authenticationConverter.convert(request);
		if (authentication == null) {
			Saml2Error saml2Error = new Saml2Error(Saml2ErrorCodes.RELYING_PARTY_REGISTRATION_NOT_FOUND,
					"No relying party registration found");
			throw new Saml2AuthenticationException(saml2Error);
		}
		setDetails(request, authentication);
		this.authenticationRequestRepository.removeAuthenticationRequest(request, response);
		return getAuthenticationManager().authenticate(authentication);
	}

	/**
	 * Use the given {@link Saml2AuthenticationRequestRepository} to remove the saved
	 * authentication request. If the {@link #authenticationConverter} is of the type
	 * {@link Saml2AuthenticationTokenConverter}, the
	 * {@link Saml2AuthenticationRequestRepository} will also be set into the
	 * {@link #authenticationConverter}.
	 * @param authenticationRequestRepository the
	 * {@link Saml2AuthenticationRequestRepository} to use
	 * @since 5.6
	 */
	public void setAuthenticationRequestRepository(
			Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository) {
		Assert.notNull(authenticationRequestRepository, "authenticationRequestRepository cannot be null");
		this.authenticationRequestRepository = authenticationRequestRepository;
		setAuthenticationRequestRepositoryIntoAuthenticationConverter(authenticationRequestRepository);
	}

	private void setAuthenticationRequestRepositoryIntoAuthenticationConverter(
			Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> authenticationRequestRepository) {
		if (this.authenticationConverter instanceof Saml2AuthenticationTokenConverter) {
			Saml2AuthenticationTokenConverter authenticationTokenConverter = (Saml2AuthenticationTokenConverter) this.authenticationConverter;
			authenticationTokenConverter.setAuthenticationRequestRepository(authenticationRequestRepository);
		}
	}

	private void setDetails(HttpServletRequest request, Authentication authentication) {
		if (AbstractAuthenticationToken.class.isAssignableFrom(authentication.getClass())) {
			Object details = this.authenticationDetailsSource.buildDetails(request);
			((AbstractAuthenticationToken) authentication).setDetails(details);
		}
	}

}
