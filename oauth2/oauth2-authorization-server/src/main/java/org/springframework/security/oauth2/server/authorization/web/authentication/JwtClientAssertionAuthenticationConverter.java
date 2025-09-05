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
 * Attempts to extract a JWT client assertion credential from {@link HttpServletRequest}
 * and then converts to an {@link OAuth2ClientAuthenticationToken} used for authenticating
 * the client.
 *
 * @author Rafal Lewczuk
 * @since 0.2.2
 * @see AuthenticationConverter
 * @see OAuth2ClientAuthenticationToken
 * @see OAuth2ClientAuthenticationFilter
 */
public final class JwtClientAssertionAuthenticationConverter implements AuthenticationConverter {

	private static final ClientAuthenticationMethod JWT_CLIENT_ASSERTION_AUTHENTICATION_METHOD = new ClientAuthenticationMethod(
			"urn:ietf:params:oauth:client-assertion-type:jwt-bearer");

	@Nullable
	@Override
	public Authentication convert(HttpServletRequest request) {
		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getFormParameters(request);

		if (parameters.getFirst(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE) == null
				|| parameters.getFirst(OAuth2ParameterNames.CLIENT_ASSERTION) == null) {
			return null;
		}

		// client_assertion_type (REQUIRED)
		String clientAssertionType = parameters.getFirst(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE);
		if (parameters.get(OAuth2ParameterNames.CLIENT_ASSERTION_TYPE).size() != 1) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}
		if (!JWT_CLIENT_ASSERTION_AUTHENTICATION_METHOD.getValue().equals(clientAssertionType)) {
			return null;
		}

		// client_assertion (REQUIRED)
		String jwtAssertion = parameters.getFirst(OAuth2ParameterNames.CLIENT_ASSERTION);
		if (parameters.get(OAuth2ParameterNames.CLIENT_ASSERTION).size() != 1) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		// client_id (OPTIONAL as per specification but REQUIRED by this implementation)
		String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
		if (!StringUtils.hasText(clientId) || parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		Map<String, Object> additionalParameters = OAuth2EndpointUtils
			.getParametersIfMatchesAuthorizationCodeGrantRequest(request, OAuth2ParameterNames.CLIENT_ASSERTION_TYPE,
					OAuth2ParameterNames.CLIENT_ASSERTION, OAuth2ParameterNames.CLIENT_ID);

		return new OAuth2ClientAuthenticationToken(clientId, JWT_CLIENT_ASSERTION_AUTHENTICATION_METHOD, jwtAssertion,
				additionalParameters);
	}

}
