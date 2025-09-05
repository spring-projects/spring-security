/*
 * Copyright 2020-2023 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.oidc.web.authentication;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.http.converter.OidcClientRegistrationHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcClientRegistrationEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Attempts to extract an OpenID Connect 1.0 Dynamic Client Registration (or Client Read)
 * Request from {@link HttpServletRequest} and then converts to an
 * {@link OidcClientRegistrationAuthenticationToken} used for authenticating the request.
 *
 * @author Joe Grandja
 * @since 0.4.0
 * @see AuthenticationConverter
 * @see OidcClientRegistrationAuthenticationToken
 * @see OidcClientRegistrationEndpointFilter
 */
public final class OidcClientRegistrationAuthenticationConverter implements AuthenticationConverter {

	private final HttpMessageConverter<OidcClientRegistration> clientRegistrationHttpMessageConverter = new OidcClientRegistrationHttpMessageConverter();

	@Override
	public Authentication convert(HttpServletRequest request) {
		Authentication principal = SecurityContextHolder.getContext().getAuthentication();

		if ("POST".equals(request.getMethod())) {
			OidcClientRegistration clientRegistration;
			try {
				clientRegistration = this.clientRegistrationHttpMessageConverter.read(OidcClientRegistration.class,
						new ServletServerHttpRequest(request));
			}
			catch (Exception ex) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
						"OpenID Client Registration Error: " + ex.getMessage(),
						"https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationError");
				throw new OAuth2AuthenticationException(error, ex);
			}
			return new OidcClientRegistrationAuthenticationToken(principal, clientRegistration);
		}

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getQueryParameters(request);

		// client_id (REQUIRED)
		String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
		if (!StringUtils.hasText(clientId) || parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		return new OidcClientRegistrationAuthenticationToken(principal, clientId);
	}

}
