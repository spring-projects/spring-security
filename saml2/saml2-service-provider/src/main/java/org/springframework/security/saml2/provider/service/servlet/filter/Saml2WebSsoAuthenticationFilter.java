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

import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2Error;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.springframework.security.saml2.provider.service.authentication.Saml2ErrorCodes.RELYING_PARTY_REGISTRATION_NOT_FOUND;
import static org.springframework.util.StringUtils.hasText;

/**
 * @since 5.2
 */
public class Saml2WebSsoAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	public static final String DEFAULT_FILTER_PROCESSES_URI = "/login/saml2/sso/{registrationId}";
	private final RequestMatcher matcher;
	private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

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
		super(filterProcessesUrl);
		Assert.notNull(relyingPartyRegistrationRepository, "relyingPartyRegistrationRepository cannot be null");
		Assert.hasText(filterProcessesUrl, "filterProcessesUrl must contain a URL pattern");
		Assert.isTrue(
				filterProcessesUrl.contains("{registrationId}"),
				"filterProcessesUrl must contain a {registrationId} match variable"
		);
		this.matcher = new AntPathRequestMatcher(filterProcessesUrl);
		setRequiresAuthenticationRequestMatcher(this.matcher);
		this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
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
		String saml2Response = request.getParameter("SAMLResponse");
		byte[] b = Saml2Utils.samlDecode(saml2Response);

		String responseXml = inflateIfRequired(request, b);
		String registrationId = this.matcher.matcher(request).getVariables().get("registrationId");
		RelyingPartyRegistration rp =
				this.relyingPartyRegistrationRepository.findByRegistrationId(registrationId);
		if (rp == null) {
			Saml2Error saml2Error = new Saml2Error(RELYING_PARTY_REGISTRATION_NOT_FOUND,
					"Relying Party Registration not found with ID: " + registrationId);
			throw new Saml2AuthenticationException(saml2Error);
		}
		String localSpEntityId = Saml2ServletUtils.getServiceProviderEntityId(rp, request);
		final Saml2AuthenticationToken authentication = new Saml2AuthenticationToken(
				responseXml,
				request.getRequestURL().toString(),
				rp.getRemoteIdpEntityId(),
				localSpEntityId,
				rp.getCredentials()
		);
		return getAuthenticationManager().authenticate(authentication);
	}

	private String inflateIfRequired(HttpServletRequest request, byte[] b) {
		if (HttpMethod.GET.matches(request.getMethod())) {
			return Saml2Utils.samlInflate(b);
		}
		else {
			return new String(b, UTF_8);
		}
	}

}
