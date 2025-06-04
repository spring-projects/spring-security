/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class DPoPAuthenticationConverter implements AuthenticationConverter {
	private static final Pattern AUTHORIZATION_PATTERN = Pattern.compile("^DPoP (?<token>[a-zA-Z0-9-._~+/]+=*)$",
			Pattern.CASE_INSENSITIVE);

	@Override
	public Authentication convert(HttpServletRequest request) {
		List<String> authorizationList = Collections.list(request.getHeaders(HttpHeaders.AUTHORIZATION));
		if (CollectionUtils.isEmpty(authorizationList)) {
			return null;
		}
		if (authorizationList.size() != 1) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
					"Found multiple Authorization headers.", null);
			throw new OAuth2AuthenticationException(error);
		}
		String authorization = authorizationList.get(0);
		if (!StringUtils.startsWithIgnoreCase(authorization, OAuth2AccessToken.TokenType.DPOP.getValue())) {
			return null;
		}
		Matcher matcher = AUTHORIZATION_PATTERN.matcher(authorization);
		if (!matcher.matches()) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, "DPoP access token is malformed.",
					null);
			throw new OAuth2AuthenticationException(error);
		}
		String accessToken = matcher.group("token");
		List<String> dPoPProofList = Collections
				.list(request.getHeaders(OAuth2AccessToken.TokenType.DPOP.getValue()));
		if (CollectionUtils.isEmpty(dPoPProofList) || dPoPProofList.size() != 1) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
					"DPoP proof is missing or invalid.", null);
			throw new OAuth2AuthenticationException(error);
		}
		String dPoPProof = dPoPProofList.get(0);
		return new DPoPAuthenticationToken(accessToken, dPoPProof, request.getMethod(),
				request.getRequestURL().toString());
	}
}
