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

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenIntrospectionEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Attempts to extract an Introspection Request from {@link HttpServletRequest} and then
 * converts it to an {@link OAuth2TokenIntrospectionAuthenticationToken} used for
 * authenticating the request.
 *
 * @author Gerardo Roza
 * @author Joe Grandja
 * @since 0.4.0
 * @see AuthenticationConverter
 * @see OAuth2TokenIntrospectionAuthenticationToken
 * @see OAuth2TokenIntrospectionEndpointFilter
 */
public final class OAuth2TokenIntrospectionAuthenticationConverter implements AuthenticationConverter {

	@Override
	public Authentication convert(HttpServletRequest request) {
		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getFormParameters(request);

		// token (REQUIRED)
		String token = parameters.getFirst(OAuth2ParameterNames.TOKEN);
		if (!StringUtils.hasText(token) || parameters.get(OAuth2ParameterNames.TOKEN).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.TOKEN);
		}

		// token_type_hint (OPTIONAL)
		String tokenTypeHint = parameters.getFirst(OAuth2ParameterNames.TOKEN_TYPE_HINT);
		if (StringUtils.hasText(tokenTypeHint) && parameters.get(OAuth2ParameterNames.TOKEN_TYPE_HINT).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.TOKEN_TYPE_HINT);
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			if (!key.equals(OAuth2ParameterNames.TOKEN) && !key.equals(OAuth2ParameterNames.TOKEN_TYPE_HINT)) {
				additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
			}
		});

		return new OAuth2TokenIntrospectionAuthenticationToken(token, clientPrincipal, tokenTypeHint,
				additionalParameters);
	}

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Token Introspection Parameter: " + parameterName,
				"https://datatracker.ietf.org/doc/html/rfc7662#section-2.1");
		throw new OAuth2AuthenticationException(error);
	}

}
