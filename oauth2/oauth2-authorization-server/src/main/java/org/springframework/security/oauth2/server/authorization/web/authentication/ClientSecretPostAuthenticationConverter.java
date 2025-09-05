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
package org.springframework.security.oauth2.server.authorization.web.authentication;

import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Attempts to extract client credentials from POST parameters of
 * {@link HttpServletRequest} and then converts to an
 * {@link OAuth2ClientAuthenticationToken} used for authenticating the client.
 *
 * @author Anoop Garlapati
 * @since 0.1.0
 * @see AuthenticationConverter
 * @see OAuth2ClientAuthenticationToken
 * @see OAuth2ClientAuthenticationFilter
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-2.3.1">Section 2.3.1 Client Password</a>
 */
public final class ClientSecretPostAuthenticationConverter implements AuthenticationConverter {

	@Nullable
	@Override
	public Authentication convert(HttpServletRequest request) {
		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getFormParameters(request);

		// client_id (REQUIRED)
		String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
		if (!StringUtils.hasText(clientId)) {
			return null;
		}

		if (parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		// client_secret (REQUIRED)
		String clientSecret = parameters.getFirst(OAuth2ParameterNames.CLIENT_SECRET);
		if (!StringUtils.hasText(clientSecret)) {
			return null;
		}

		if (parameters.get(OAuth2ParameterNames.CLIENT_SECRET).size() != 1) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		Map<String, Object> additionalParameters = OAuth2EndpointUtils
			.getParametersIfMatchesAuthorizationCodeGrantRequest(request, OAuth2ParameterNames.CLIENT_ID,
					OAuth2ParameterNames.CLIENT_SECRET);

		return new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.CLIENT_SECRET_POST,
				clientSecret, additionalParameters);
	}

}
