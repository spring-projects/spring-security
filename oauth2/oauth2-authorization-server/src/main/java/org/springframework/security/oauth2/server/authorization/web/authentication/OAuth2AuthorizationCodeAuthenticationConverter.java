/*
 * Copyright 2004-present the original author or authors.
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
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Attempts to extract an Access Token Request from {@link HttpServletRequest} for the
 * OAuth 2.0 Authorization Code Grant and then converts it to an
 * {@link OAuth2AuthorizationCodeAuthenticationToken} used for authenticating the
 * authorization grant.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see AuthenticationConverter
 * @see OAuth2AuthorizationCodeAuthenticationToken
 * @see OAuth2TokenEndpointFilter
 */
public final class OAuth2AuthorizationCodeAuthenticationConverter implements AuthenticationConverter {

	@Override
	public @Nullable Authentication convert(HttpServletRequest request) {
		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getFormParameters(request);

		// grant_type (REQUIRED)
		String grantType = parameters.getFirst(OAuth2ParameterNames.GRANT_TYPE);
		if (!AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(grantType)) {
			return null;
		}

		// code (REQUIRED)
		String code = parameters.getFirst(OAuth2ParameterNames.CODE);
		List<String> codeParams = parameters.get(OAuth2ParameterNames.CODE);
		if (!StringUtils.hasText(code) || codeParams == null || codeParams.size() != 1) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CODE,
					OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
		}
		Assert.notNull(code, "code cannot be null");

		// redirect_uri (REQUIRED)
		// Required only if the "redirect_uri" parameter was included in the authorization
		// request
		String redirectUri = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
		List<String> redirectUriParams = parameters.get(OAuth2ParameterNames.REDIRECT_URI);
		if (StringUtils.hasText(redirectUri) && redirectUriParams != null && redirectUriParams.size() != 1) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI,
					OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) && !key.equals(OAuth2ParameterNames.CLIENT_ID)
					&& !key.equals(OAuth2ParameterNames.CODE) && !key.equals(OAuth2ParameterNames.REDIRECT_URI)) {
				additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
			}
		});

		// Validate DPoP Proof HTTP Header (if available)
		OAuth2EndpointUtils.validateAndAddDPoPParametersIfAvailable(request, additionalParameters);

		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");

		return new OAuth2AuthorizationCodeAuthenticationToken(code, clientPrincipal, redirectUri, additionalParameters);
	}

}
