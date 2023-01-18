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

package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationConverter} that extracts the OIDC Logout Token authentication
 * request
 *
 * @author Josh Cummings
 * @since 6.2
 */
final class OidcLogoutAuthenticationConverter implements AuthenticationConverter {

	private static final String DEFAULT_LOGOUT_URI = "/logout/connect/back-channel/{registrationId}";

	private final Log logger = LogFactory.getLog(getClass());

	private final ClientRegistrationRepository clientRegistrationRepository;

	private RequestMatcher requestMatcher = new AntPathRequestMatcher(DEFAULT_LOGOUT_URI, "POST");

	OidcLogoutAuthenticationConverter(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@Override
	public Authentication convert(HttpServletRequest request) {
		RequestMatcher.MatchResult result = this.requestMatcher.matcher(request);
		if (!result.isMatch()) {
			return null;
		}
		String registrationId = result.getVariables().get("registrationId");
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
		if (clientRegistration == null) {
			this.logger.debug("Did not process OIDC Back-Channel Logout since no ClientRegistration was found");
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}
		String logoutToken = request.getParameter("logout_token");
		if (logoutToken == null) {
			this.logger.debug("Failed to process OIDC Back-Channel Logout since no logout token was found");
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}
		return new OidcLogoutAuthenticationToken(logoutToken, clientRegistration);
	}

	/**
	 * The logout endpoint. Defaults to
	 * {@code /logout/connect/back-channel/{registrationId}}.
	 * @param requestMatcher the {@link RequestMatcher} to use
	 */
	void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

}
