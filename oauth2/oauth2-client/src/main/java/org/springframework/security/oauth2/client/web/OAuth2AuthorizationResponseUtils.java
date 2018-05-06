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

import org.springframework.security.oauth2.client.registration.ClientRegistration.ProviderDetails;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
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

	static boolean isAuthorizationResponse(HttpServletRequest request, ProviderDetails providerDetails) {
		return isAuthorizationResponseSuccess(request, providerDetails) || isAuthorizationResponseError(request, providerDetails);
	}

	static boolean isAuthorizationResponseSuccess(HttpServletRequest request, ProviderDetails providerDetails) {
		return StringUtils.hasText(request.getParameter(providerDetails.getCodeAttributeName())) &&
			StringUtils.hasText(request.getParameter(providerDetails.getStateAttributeName()));
	}

	static boolean isAuthorizationResponseError(HttpServletRequest request, ProviderDetails providerDetails) {
		return StringUtils.hasText(request.getParameter(providerDetails.getErrorAttributeName())) &&
			StringUtils.hasText(request.getParameter(providerDetails.getStateAttributeName()));
	}

	static OAuth2AuthorizationResponse convert(HttpServletRequest request, ProviderDetails providerDetails) {
		String code = request.getParameter(providerDetails.getCodeAttributeName());
		String errorCode = request.getParameter(providerDetails.getErrorAttributeName());
		String state = request.getParameter(providerDetails.getStateAttributeName());
		String redirectUri = request.getRequestURL().toString();

		if (StringUtils.hasText(code)) {
			return OAuth2AuthorizationResponse.success(code)
				.redirectUri(redirectUri)
				.state(state)
				.build();
		} else {
			String errorDescription = request.getParameter(providerDetails.getErrorDescriptionAttributeName());
			String errorUri = request.getParameter(providerDetails.getErrorUriAttributeName());
			return OAuth2AuthorizationResponse.error(errorCode)
				.redirectUri(redirectUri)
				.errorDescription(errorDescription)
				.errorUri(errorUri)
				.state(state)
				.build();
		}
	}
}
