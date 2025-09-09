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
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Attempts to extract an Authorization Consent from {@link HttpServletRequest} for the
 * OAuth 2.0 Authorization Code Grant and then converts it to an
 * {@link OAuth2AuthorizationConsentAuthenticationToken} used for authenticating the
 * request.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see AuthenticationConverter
 * @see OAuth2AuthorizationConsentAuthenticationToken
 * @see OAuth2AuthorizationEndpointFilter
 */
public final class OAuth2AuthorizationConsentAuthenticationConverter implements AuthenticationConverter {

	private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";

	private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken("anonymous",
			"anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	private final RequestMatcher requestMatcher = createDefaultRequestMatcher();

	@Override
	public Authentication convert(HttpServletRequest request) {
		if (!this.requestMatcher.matches(request)) {
			return null;
		}

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getFormParameters(request);

		String authorizationUri = request.getRequestURL().toString();

		// client_id (REQUIRED)
		String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
		if (!StringUtils.hasText(clientId) || parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
		}

		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		if (principal == null) {
			principal = ANONYMOUS_AUTHENTICATION;
		}

		// state (REQUIRED)
		String state = parameters.getFirst(OAuth2ParameterNames.STATE);
		if (!StringUtils.hasText(state) || parameters.get(OAuth2ParameterNames.STATE).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
		}

		// scope (OPTIONAL)
		Set<String> scopes = null;
		if (parameters.containsKey(OAuth2ParameterNames.SCOPE)) {
			scopes = new HashSet<>(parameters.get(OAuth2ParameterNames.SCOPE));
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			if (!key.equals(OAuth2ParameterNames.CLIENT_ID) && !key.equals(OAuth2ParameterNames.STATE)
					&& !key.equals(OAuth2ParameterNames.SCOPE)) {
				additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
			}
		});

		return new OAuth2AuthorizationConsentAuthenticationToken(authorizationUri, clientId, principal, state, scopes,
				additionalParameters);
	}

	private static RequestMatcher createDefaultRequestMatcher() {
		RequestMatcher postMethodMatcher = (request) -> "POST".equals(request.getMethod());
		RequestMatcher responseTypeParameterMatcher = (
				request) -> request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;
		return new AndRequestMatcher(postMethodMatcher, new NegatedRequestMatcher(responseTypeParameterMatcher));
	}

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, DEFAULT_ERROR_URI);
		throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
	}

}
