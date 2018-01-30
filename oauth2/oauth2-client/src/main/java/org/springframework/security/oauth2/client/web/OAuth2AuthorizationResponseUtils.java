/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.web;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;

/**
 * Utility methods for an OAuth 2.0 Authorization Response.
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AuthorizationResponse
 */
final class OAuth2AuthorizationResponseUtils {

	private OAuth2AuthorizationResponseUtils() {
	}

	static boolean authorizationResponse(HttpServletRequest request) {
		return authorizationResponseSuccess(request) || authorizationResponseError(request);
	}

	static boolean authorizationResponseSuccess(HttpServletRequest request) {
		return StringUtils.hasText(request.getParameter(OAuth2ParameterNames.CODE)) &&
			StringUtils.hasText(request.getParameter(OAuth2ParameterNames.STATE));
	}

	static boolean authorizationResponseError(HttpServletRequest request) {
		return StringUtils.hasText(request.getParameter(OAuth2ParameterNames.ERROR)) &&
			StringUtils.hasText(request.getParameter(OAuth2ParameterNames.STATE));
	}

	static OAuth2AuthorizationResponse convert(HttpServletRequest request) {
		String code = request.getParameter(OAuth2ParameterNames.CODE);
		String errorCode = request.getParameter(OAuth2ParameterNames.ERROR);
		String state = request.getParameter(OAuth2ParameterNames.STATE);
		String redirectUri = request.getRequestURL().toString();

		if (StringUtils.hasText(code)) {
			return OAuth2AuthorizationResponse.success(code)
				.redirectUri(redirectUri)
				.state(state)
				.build();
		} else {
			String errorDescription = request.getParameter(OAuth2ParameterNames.ERROR_DESCRIPTION);
			String errorUri = request.getParameter(OAuth2ParameterNames.ERROR_URI);
			return OAuth2AuthorizationResponse.error(errorCode)
				.redirectUri(redirectUri)
				.errorDescription(errorDescription)
				.errorUri(errorUri)
				.state(state)
				.build();
		}
	}
}
