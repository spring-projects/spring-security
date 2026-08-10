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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2DeviceAuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2DeviceVerificationEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Attempts to extract a Device Authorization Consent from {@link HttpServletRequest} for
 * the OAuth 2.0 Device Authorization Grant and then converts it to an
 * {@link OAuth2DeviceAuthorizationConsentAuthenticationToken} used for authenticating the
 * request.
 *
 * @author Steve Riesenberg
 * @since 7.0
 * @see AuthenticationConverter
 * @see OAuth2DeviceAuthorizationConsentAuthenticationToken
 * @see OAuth2DeviceVerificationEndpointFilter
 */
public final class OAuth2DeviceAuthorizationConsentAuthenticationConverter implements AuthenticationConverter {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken("anonymous",
			"anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	@Override
	public @Nullable Authentication convert(HttpServletRequest request) {
		if (!"POST".equals(request.getMethod()) || request.getParameter(OAuth2ParameterNames.STATE) == null) {
			return null;
		}

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getFormParameters(request);

		String authorizationUri = request.getRequestURL().toString();

		// client_id (REQUIRED)
		String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
		List<String> clientIdParams = parameters.get(OAuth2ParameterNames.CLIENT_ID);
		if (!StringUtils.hasText(clientId) || clientIdParams == null || clientIdParams.size() != 1) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID, ERROR_URI);
		}
		Assert.notNull(clientId, "clientId cannot be null");

		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		if (principal == null) {
			principal = ANONYMOUS_AUTHENTICATION;
		}

		// user_code (REQUIRED)
		String userCode = parameters.getFirst(OAuth2ParameterNames.USER_CODE);
		List<String> userCodeParams = parameters.get(OAuth2ParameterNames.USER_CODE);
		if (userCode == null || !OAuth2EndpointUtils.validateUserCode(userCode) || userCodeParams == null
				|| userCodeParams.size() != 1) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.USER_CODE, ERROR_URI);
		}
		Assert.notNull(userCode, "userCode cannot be null");

		// state (REQUIRED)
		String state = parameters.getFirst(OAuth2ParameterNames.STATE);
		List<String> stateParams = parameters.get(OAuth2ParameterNames.STATE);
		if (!StringUtils.hasText(state) || stateParams == null || stateParams.size() != 1) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE, ERROR_URI);
		}
		Assert.notNull(state, "state cannot be null");

		// scope (OPTIONAL)
		Set<String> scopes = null;
		if (parameters.containsKey(OAuth2ParameterNames.SCOPE)) {
			scopes = new HashSet<>(parameters.get(OAuth2ParameterNames.SCOPE));
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			if (!key.equals(OAuth2ParameterNames.CLIENT_ID) && !key.equals(OAuth2ParameterNames.USER_CODE)
					&& !key.equals(OAuth2ParameterNames.STATE) && !key.equals(OAuth2ParameterNames.SCOPE)) {
				additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
			}
		});

		return new OAuth2DeviceAuthorizationConsentAuthenticationToken(authorizationUri, clientId, principal,
				OAuth2EndpointUtils.normalizeUserCode(userCode), state, scopes, additionalParameters);
	}

}
