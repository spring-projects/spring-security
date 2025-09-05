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

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Attempts to extract the parameters from {@link HttpServletRequest} used for
 * authenticating public clients using Proof Key for Code Exchange (PKCE).
 *
 * @author Joe Grandja
 * @since 0.0.2
 * @see AuthenticationConverter
 * @see OAuth2ClientAuthenticationToken
 * @see OAuth2ClientAuthenticationFilter
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7636">Proof Key for Code
 * Exchange by OAuth Public Clients</a>
 */
public final class PublicClientAuthenticationConverter implements AuthenticationConverter {

	@Nullable
	@Override
	public Authentication convert(HttpServletRequest request) {
		if (!OAuth2EndpointUtils.matchesPkceTokenRequest(request)) {
			return null;
		}

		MultiValueMap<String, String> parameters = "GET".equals(request.getMethod())
				? OAuth2EndpointUtils.getQueryParameters(request) : OAuth2EndpointUtils.getFormParameters(request);

		// client_id (REQUIRED for public clients)
		String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
		if (!StringUtils.hasText(clientId) || parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		// code_verifier (REQUIRED)
		if (parameters.get(PkceParameterNames.CODE_VERIFIER).size() != 1) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		parameters.remove(OAuth2ParameterNames.CLIENT_ID);

		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> additionalParameters.put(key,
				(value.size() == 1) ? value.get(0) : value.toArray(new String[0])));

		return new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.NONE, null,
				additionalParameters);
	}

}
