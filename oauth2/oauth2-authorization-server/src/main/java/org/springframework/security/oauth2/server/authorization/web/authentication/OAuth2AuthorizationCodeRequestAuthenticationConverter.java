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
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2PushedAuthorizationRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2PushedAuthorizationRequestEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.CollectionUtils;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Attempts to extract an Authorization Request from {@link HttpServletRequest} for the
 * OAuth 2.0 Authorization Code Grant and then converts it to an
 * {@link OAuth2AuthorizationCodeRequestAuthenticationToken} OR
 * {@link OAuth2PushedAuthorizationRequestAuthenticationToken} used for authenticating the
 * request.
 *
 * @author Joe Grandja
 * @since 0.1.2
 * @see AuthenticationConverter
 * @see OAuth2AuthorizationCodeRequestAuthenticationToken
 * @see OAuth2PushedAuthorizationRequestAuthenticationToken
 * @see OAuth2AuthorizationEndpointFilter
 * @see OAuth2PushedAuthorizationRequestEndpointFilter
 */
public final class OAuth2AuthorizationCodeRequestAuthenticationConverter implements AuthenticationConverter {

	private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";

	private static final String PKCE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1";

	private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken("anonymous",
			"anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	private final RequestMatcher requestMatcher = createDefaultRequestMatcher();

	@Override
	public Authentication convert(HttpServletRequest request) {
		if (!this.requestMatcher.matches(request)) {
			return null;
		}

		MultiValueMap<String, String> parameters = "GET".equals(request.getMethod())
				? OAuth2EndpointUtils.getQueryParameters(request) : OAuth2EndpointUtils.getFormParameters(request);

		boolean pushedAuthorizationRequest = isPushedAuthorizationRequest(request);

		// request_uri (OPTIONAL) - provided if an authorization request was previously
		// pushed (RFC 9126 OAuth 2.0 Pushed Authorization Requests)
		String requestUri = parameters.getFirst(OAuth2ParameterNames.REQUEST_URI);
		if (StringUtils.hasText(requestUri)) {
			if (pushedAuthorizationRequest) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REQUEST_URI);
			}
			else if (parameters.get(OAuth2ParameterNames.REQUEST_URI).size() != 1) {
				// Authorization Request
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REQUEST_URI);
			}
		}

		if (!StringUtils.hasText(requestUri)) {
			// response_type (REQUIRED)
			String responseType = parameters.getFirst(OAuth2ParameterNames.RESPONSE_TYPE);
			if (!StringUtils.hasText(responseType) || parameters.get(OAuth2ParameterNames.RESPONSE_TYPE).size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.RESPONSE_TYPE);
			}
			else if (!responseType.equals(OAuth2AuthorizationResponseType.CODE.getValue())) {
				throwError(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, OAuth2ParameterNames.RESPONSE_TYPE);
			}
		}

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

		// redirect_uri (OPTIONAL)
		String redirectUri = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
		if (StringUtils.hasText(redirectUri) && parameters.get(OAuth2ParameterNames.REDIRECT_URI).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI);
		}

		// scope (OPTIONAL)
		Set<String> scopes = null;
		String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
		if (StringUtils.hasText(scope) && parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE);
		}
		if (StringUtils.hasText(scope)) {
			scopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
		}

		// state (RECOMMENDED)
		String state = parameters.getFirst(OAuth2ParameterNames.STATE);
		if (StringUtils.hasText(state) && parameters.get(OAuth2ParameterNames.STATE).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
		}

		// code_challenge (REQUIRED for public clients) - RFC 7636 (PKCE)
		String codeChallenge = parameters.getFirst(PkceParameterNames.CODE_CHALLENGE);
		if (StringUtils.hasText(codeChallenge) && parameters.get(PkceParameterNames.CODE_CHALLENGE).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE, PKCE_ERROR_URI);
		}

		// code_challenge_method (OPTIONAL for public clients) - RFC 7636 (PKCE)
		String codeChallengeMethod = parameters.getFirst(PkceParameterNames.CODE_CHALLENGE_METHOD);
		if (StringUtils.hasText(codeChallengeMethod)
				&& parameters.get(PkceParameterNames.CODE_CHALLENGE_METHOD).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE_METHOD, PKCE_ERROR_URI);
		}

		// prompt (OPTIONAL for OpenID Connect 1.0 Authentication Request)
		if (!CollectionUtils.isEmpty(scopes) && scopes.contains(OidcScopes.OPENID)) {
			String prompt = parameters.getFirst("prompt");
			if (StringUtils.hasText(prompt) && parameters.get("prompt").size() != 1) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, "prompt");
			}
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			if (!key.equals(OAuth2ParameterNames.RESPONSE_TYPE) && !key.equals(OAuth2ParameterNames.CLIENT_ID)
					&& !key.equals(OAuth2ParameterNames.REDIRECT_URI) && !key.equals(OAuth2ParameterNames.SCOPE)
					&& !key.equals(OAuth2ParameterNames.STATE)) {
				additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
			}
		});

		if (pushedAuthorizationRequest) {
			return new OAuth2PushedAuthorizationRequestAuthenticationToken(authorizationUri, clientId, principal,
					redirectUri, state, scopes, additionalParameters);
		}
		else {
			return new OAuth2AuthorizationCodeRequestAuthenticationToken(authorizationUri, clientId, principal,
					redirectUri, state, scopes, additionalParameters);
		}
	}

	private boolean isPushedAuthorizationRequest(HttpServletRequest request) {
		AuthorizationServerContext authorizationServerContext = AuthorizationServerContextHolder.getContext();
		AuthorizationServerSettings authorizationServerSettings = authorizationServerContext
			.getAuthorizationServerSettings();
		return request.getRequestURL()
			.toString()
			.toLowerCase(Locale.ROOT)
			.endsWith(authorizationServerSettings.getPushedAuthorizationRequestEndpoint().toLowerCase(Locale.ROOT));
	}

	private static RequestMatcher createDefaultRequestMatcher() {
		RequestMatcher getMethodMatcher = (request) -> "GET".equals(request.getMethod());
		RequestMatcher postMethodMatcher = (request) -> "POST".equals(request.getMethod());
		RequestMatcher responseTypeParameterMatcher = (
				request) -> request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;
		return new OrRequestMatcher(getMethodMatcher,
				new AndRequestMatcher(postMethodMatcher, responseTypeParameterMatcher));
	}

	private static void throwError(String errorCode, String parameterName) {
		throwError(errorCode, parameterName, DEFAULT_ERROR_URI);
	}

	private static void throwError(String errorCode, String parameterName, String errorUri) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
		throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
	}

}
