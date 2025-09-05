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
package org.springframework.security.oauth2.server.authorization.oidc.web.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcLogoutEndpointFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

/**
 * Attempts to extract an OpenID Connect 1.0 RP-Initiated Logout Request from
 * {@link HttpServletRequest} and then converts to an
 * {@link OidcLogoutAuthenticationToken} used for authenticating the request.
 *
 * @author Joe Grandja
 * @since 1.1
 * @see AuthenticationConverter
 * @see OidcLogoutAuthenticationToken
 * @see OidcLogoutEndpointFilter
 */
public final class OidcLogoutAuthenticationConverter implements AuthenticationConverter {

	private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken("anonymous",
			"anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	@Override
	public Authentication convert(HttpServletRequest request) {
		MultiValueMap<String, String> parameters = "GET".equals(request.getMethod())
				? OAuth2EndpointUtils.getQueryParameters(request) : OAuth2EndpointUtils.getFormParameters(request);

		// id_token_hint (REQUIRED) // RECOMMENDED as per spec
		String idTokenHint = parameters.getFirst("id_token_hint");
		if (!StringUtils.hasText(idTokenHint) || parameters.get("id_token_hint").size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, "id_token_hint");
		}

		Authentication principal = SecurityContextHolder.getContext().getAuthentication();
		if (principal == null) {
			principal = ANONYMOUS_AUTHENTICATION;
		}

		String sessionId = null;
		HttpSession session = request.getSession(false);
		if (session != null) {
			sessionId = session.getId();
		}

		// client_id (OPTIONAL)
		String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
		if (StringUtils.hasText(clientId) && parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.CLIENT_ID);
		}

		// post_logout_redirect_uri (OPTIONAL)
		String postLogoutRedirectUri = parameters.getFirst("post_logout_redirect_uri");
		if (StringUtils.hasText(postLogoutRedirectUri) && parameters.get("post_logout_redirect_uri").size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, "post_logout_redirect_uri");
		}

		// state (OPTIONAL)
		String state = parameters.getFirst(OAuth2ParameterNames.STATE);
		if (StringUtils.hasText(state) && parameters.get(OAuth2ParameterNames.STATE).size() != 1) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
		}

		return new OidcLogoutAuthenticationToken(idTokenHint, principal, sessionId, clientId, postLogoutRedirectUri,
				state);
	}

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OpenID Connect 1.0 Logout Request Parameter: " + parameterName,
				"https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling");
		throw new OAuth2AuthenticationException(error);
	}

}
