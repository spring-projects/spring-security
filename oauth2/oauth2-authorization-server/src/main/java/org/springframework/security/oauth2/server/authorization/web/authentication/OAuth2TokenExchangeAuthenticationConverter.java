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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.CollectionUtils;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Attempts to extract an Access Token Request from {@link HttpServletRequest} for the
 * OAuth 2.0 Token Exchange Grant and then converts it to an
 * {@link OAuth2TokenExchangeAuthenticationToken} used for authenticating the
 * authorization grant.
 *
 * @author Steve Riesenberg
 * @since 7.0
 * @see AuthenticationConverter
 * @see OAuth2TokenExchangeAuthenticationToken
 * @see OAuth2TokenEndpointFilter
 */
public final class OAuth2TokenExchangeAuthenticationConverter implements AuthenticationConverter {

	private static final String TOKEN_TYPE_IDENTIFIERS_URI = "https://datatracker.ietf.org/doc/html/rfc8693#section-3";

	private static final String ACCESS_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:access_token";

	private static final String JWT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt";

	private static final Set<String> SUPPORTED_TOKEN_TYPES = Set.of(ACCESS_TOKEN_TYPE_VALUE, JWT_TOKEN_TYPE_VALUE);

	@Nullable
	@Override
	public Authentication convert(HttpServletRequest request) {
		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getFormParameters(request);

		// grant_type (REQUIRED)
		String grantType = parameters.getFirst(OAuth2ParameterNames.GRANT_TYPE);
		if (!AuthorizationGrantType.TOKEN_EXCHANGE.getValue().equals(grantType)) {
			return null;
		}

		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

		// resource (OPTIONAL)
		List<String> resources = parameters.getOrDefault(OAuth2ParameterNames.RESOURCE, Collections.emptyList());
		if (!CollectionUtils.isEmpty(resources)) {
			for (String resource : resources) {
				if (!isValidUri(resource)) {
					OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.RESOURCE,
							OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
				}
			}
		}

		// audience (OPTIONAL)
		List<String> audiences = parameters.getOrDefault(OAuth2ParameterNames.AUDIENCE, Collections.emptyList());

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

		// requested_token_type (OPTIONAL)
		String requestedTokenType = parameters.getFirst(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE);
		if (StringUtils.hasText(requestedTokenType)) {
			if (parameters.get(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE).size() != 1) {
				OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST,
						OAuth2ParameterNames.REQUESTED_TOKEN_TYPE, OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
			}

			validateTokenType(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE, requestedTokenType);
		}
		else {
			requestedTokenType = ACCESS_TOKEN_TYPE_VALUE;
		}

		// subject_token (REQUIRED)
		String subjectToken = parameters.getFirst(OAuth2ParameterNames.SUBJECT_TOKEN);
		if (!StringUtils.hasText(subjectToken) || parameters.get(OAuth2ParameterNames.SUBJECT_TOKEN).size() != 1) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SUBJECT_TOKEN,
					OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
		}

		// subject_token_type (REQUIRED)
		String subjectTokenType = parameters.getFirst(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE);
		if (!StringUtils.hasText(subjectTokenType)
				|| parameters.get(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE).size() != 1) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SUBJECT_TOKEN_TYPE,
					OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
		}
		else {
			validateTokenType(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE, subjectTokenType);
		}

		// actor_token (OPTIONAL, REQUIRED if actor_token_type is provided)
		String actorToken = parameters.getFirst(OAuth2ParameterNames.ACTOR_TOKEN);
		if (StringUtils.hasText(actorToken) && parameters.get(OAuth2ParameterNames.ACTOR_TOKEN).size() != 1) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.ACTOR_TOKEN,
					OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
		}

		// actor_token_type (OPTIONAL, REQUIRED if actor_token is provided)
		String actorTokenType = parameters.getFirst(OAuth2ParameterNames.ACTOR_TOKEN_TYPE);
		if (StringUtils.hasText(actorTokenType)) {
			if (parameters.get(OAuth2ParameterNames.ACTOR_TOKEN_TYPE).size() != 1) {
				OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.ACTOR_TOKEN_TYPE,
						OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
			}

			validateTokenType(OAuth2ParameterNames.ACTOR_TOKEN_TYPE, actorTokenType);
		}

		if (!StringUtils.hasText(actorToken) && StringUtils.hasText(actorTokenType)) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.ACTOR_TOKEN,
					OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
		}
		else if (StringUtils.hasText(actorToken) && !StringUtils.hasText(actorTokenType)) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.ACTOR_TOKEN_TYPE,
					OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) && !key.equals(OAuth2ParameterNames.RESOURCE)
					&& !key.equals(OAuth2ParameterNames.AUDIENCE)
					&& !key.equals(OAuth2ParameterNames.REQUESTED_TOKEN_TYPE)
					&& !key.equals(OAuth2ParameterNames.SUBJECT_TOKEN)
					&& !key.equals(OAuth2ParameterNames.SUBJECT_TOKEN_TYPE)
					&& !key.equals(OAuth2ParameterNames.ACTOR_TOKEN)
					&& !key.equals(OAuth2ParameterNames.ACTOR_TOKEN_TYPE) && !key.equals(OAuth2ParameterNames.SCOPE)) {
				additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
			}
		});

		// Validate DPoP Proof HTTP Header (if available)
		OAuth2EndpointUtils.validateAndAddDPoPParametersIfAvailable(request, additionalParameters);

		return new OAuth2TokenExchangeAuthenticationToken(requestedTokenType, subjectToken, subjectTokenType,
				clientPrincipal, actorToken, actorTokenType, new LinkedHashSet<>(resources),
				new LinkedHashSet<>(audiences), requestedScopes, additionalParameters);
	}

	private static void validateTokenType(String parameterName, String tokenTypeValue) {
		if (!SUPPORTED_TOKEN_TYPES.contains(tokenTypeValue)) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.UNSUPPORTED_TOKEN_TYPE,
					String.format("OAuth 2.0 Token Exchange parameter: %s", parameterName), TOKEN_TYPE_IDENTIFIERS_URI);
			// @formatter:off
			String message = String.format(
					"OAuth 2.0 Token Exchange parameter: %s - " +
					"The provided value is not supported by this authorization server. " +
					"Supported values are %s and %s.",
					parameterName, ACCESS_TOKEN_TYPE_VALUE, JWT_TOKEN_TYPE_VALUE);
			// @formatter:on
			throw new OAuth2AuthenticationException(error, message);
		}
	}

	private static boolean isValidUri(String uri) {
		try {
			URI validUri = new URI(uri);
			return validUri.isAbsolute() && validUri.getFragment() == null;
		}
		catch (URISyntaxException ex) {
			return false;
		}
	}

}
