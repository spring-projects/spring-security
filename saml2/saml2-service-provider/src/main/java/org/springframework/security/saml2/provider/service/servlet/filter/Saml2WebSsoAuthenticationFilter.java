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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.util.Assert;

import static org.springframework.security.saml2.core.Saml2ErrorCodes.RELYING_PARTY_REGISTRATION_NOT_FOUND;
import static org.springframework.util.StringUtils.hasText;

/**
 * @since 5.2
 */
public class Saml2WebSsoAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	public static final String DEFAULT_FILTER_PROCESSES_URI = "/login/saml2/sso/{registrationId}";
	private final AuthenticationConverter authenticationConverter;

	/**
	 * Creates a {@code Saml2WebSsoAuthenticationFilter} authentication filter that is configured
	 * to use the {@link #DEFAULT_FILTER_PROCESSES_URI} processing URL
	 * @param relyingPartyRegistrationRepository - repository of configured SAML 2 entities. Required.
	 */
	public Saml2WebSsoAuthenticationFilter(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
		this(relyingPartyRegistrationRepository, DEFAULT_FILTER_PROCESSES_URI);
	}

	/**
	 * Creates a {@code Saml2WebSsoAuthenticationFilter} authentication filter
	 * @param relyingPartyRegistrationRepository - repository of configured SAML 2 entities. Required.
	 * @param filterProcessesUrl the processing URL, must contain a {registrationId} variable. Required.
	 */
	public Saml2WebSsoAuthenticationFilter(
			RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
			String filterProcessesUrl) {
		this(new Saml2AuthenticationTokenConverter
				(new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository)),
				filterProcessesUrl);
	}

	/**
	 * Creates a {@link Saml2WebSsoAuthenticationFilter} given the provided parameters
	 *
	 * @param authenticationConverter the strategy for converting an {@link HttpServletRequest}
	 * into an {@link Authentication}
	 * @param filterProcessingUrl the processing URL, must contain a {registrationId} variable
	 * @since 5.4
	 */
	public Saml2WebSsoAuthenticationFilter(
			AuthenticationConverter authenticationConverter,
			String filterProcessingUrl) {
		super(filterProcessingUrl);
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		Assert.hasText(filterProcessingUrl, "filterProcessesUrl must contain a URL pattern");
		Assert.isTrue(
				filterProcessingUrl.contains("{registrationId}"),
				"filterProcessesUrl must contain a {registrationId} match variable"
		);
		this.authenticationConverter = authenticationConverter;
		setAllowSessionCreation(true);
		setSessionAuthenticationStrategy(new ChangeSessionIdAuthenticationStrategy());
	}

	@Override
	protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
		return (super.requiresAuthentication(request, response) && hasText(request.getParameter("SAMLResponse")));
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		Authentication authentication = this.authenticationConverter.convert(request);
		if (authentication == null) {
			Saml2Error saml2Error = new Saml2Error(RELYING_PARTY_REGISTRATION_NOT_FOUND,
					"No relying party registration found");
			throw new Saml2AuthenticationException(saml2Error);
		}
		return getAuthenticationManager().authenticate(authentication);
	}
}
