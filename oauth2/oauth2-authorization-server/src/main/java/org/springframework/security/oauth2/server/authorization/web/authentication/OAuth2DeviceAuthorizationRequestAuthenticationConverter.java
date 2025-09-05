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

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2DeviceAuthorizationEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Attempts to extract a Device Authorization Request from {@link HttpServletRequest} for
 * the OAuth 2.0 Device Authorization Grant and then converts it to an
 * {@link OAuth2DeviceAuthorizationRequestAuthenticationToken} used for authenticating the
 * request.
 *
 * @author Steve Riesenberg
 * @since 1.1
 * @see AuthenticationConverter
 * @see OAuth2DeviceAuthorizationRequestAuthenticationToken
 * @see OAuth2DeviceAuthorizationEndpointFilter
 */
public final class OAuth2DeviceAuthorizationRequestAuthenticationConverter implements AuthenticationConverter {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc8628#section-3.1";

	@Override
	public Authentication convert(HttpServletRequest request) {
		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getFormParameters(request);

		String authorizationUri = request.getRequestURL().toString();

		// scope (OPTIONAL)
		String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
		if (StringUtils.hasText(scope) && parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE, ERROR_URI);
		}
		Set<String> requestedScopes = null;
		if (StringUtils.hasText(scope)) {
			requestedScopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			if (!key.equals(OAuth2ParameterNames.CLIENT_ID) && !key.equals(OAuth2ParameterNames.SCOPE)) {
				additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
			}
		});

		return new OAuth2DeviceAuthorizationRequestAuthenticationToken(clientPrincipal, authorizationUri,
				requestedScopes, additionalParameters);
	}

}
