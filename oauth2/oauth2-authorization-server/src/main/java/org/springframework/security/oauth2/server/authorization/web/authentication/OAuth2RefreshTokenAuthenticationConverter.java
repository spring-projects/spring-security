/*
 * Copyright 2020-2025 the original author or authors.
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

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Attempts to extract an Access Token Request from {@link HttpServletRequest} for the
 * OAuth 2.0 Refresh Token Grant and then converts it to an
 * {@link OAuth2RefreshTokenAuthenticationToken} used for authenticating the authorization
 * grant.
 *
 * @author Joe Grandja
 * @since 0.1.2
 * @see AuthenticationConverter
 * @see OAuth2RefreshTokenAuthenticationToken
 * @see OAuth2TokenEndpointFilter
 */
public final class OAuth2RefreshTokenAuthenticationConverter implements AuthenticationConverter {

	@Nullable
	@Override
	public Authentication convert(HttpServletRequest request) {
		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getFormParameters(request);

		// grant_type (REQUIRED)
		String grantType = parameters.getFirst(OAuth2ParameterNames.GRANT_TYPE);
		if (!AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)) {
			return null;
		}

		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

		// refresh_token (REQUIRED)
		String refreshToken = parameters.getFirst(OAuth2ParameterNames.REFRESH_TOKEN);
		if (!StringUtils.hasText(refreshToken) || parameters.get(OAuth2ParameterNames.REFRESH_TOKEN).size() != 1) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REFRESH_TOKEN,
					OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
		}

		// scope (OPTIONAL)
		String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
		if (StringUtils.hasText(scope) && parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE,
					OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
		}
		Set<String> requestedScopes = null;
		if (StringUtils.hasText(scope)) {
			requestedScopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) && !key.equals(OAuth2ParameterNames.REFRESH_TOKEN)
					&& !key.equals(OAuth2ParameterNames.SCOPE)) {
				additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
			}
		});

		// Validate DPoP Proof HTTP Header (if available)
		OAuth2EndpointUtils.validateAndAddDPoPParametersIfAvailable(request, additionalParameters);

		return new OAuth2RefreshTokenAuthenticationToken(refreshToken, clientPrincipal, requestedScopes,
				additionalParameters);
	}

}
