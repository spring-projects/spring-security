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

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Map;

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

	static MultiValueMap<String, String> toMultiMap(Map<String, String[]> map) {
		MultiValueMap<String, String> params = new LinkedMultiValueMap<>(map.size());
		map.forEach((key, values) -> {
			if (values.length > 0) {
				for (String value : values) {
					params.add(key, value);
				}
			}
		});
		return params;
	}

	static boolean isAuthorizationResponse(MultiValueMap<String, String> request, ClientRegistration clientRegistration) {
		ClientRegistration.ProviderDetails provider = clientRegistration.getProviderDetails();
		String codeAttributeName = provider.getCodeAttributeName();
		String stateAttributeName = provider.getStateAttributeName();
		String errorAttributeName = provider.getErrorAttributeName();
		return isAuthorizationResponseSuccess(request, codeAttributeName, stateAttributeName) ||
				isAuthorizationResponseError(request, errorAttributeName, stateAttributeName);
	}

	static boolean isAuthorizationResponseSuccess(MultiValueMap<String, String> request, String codeAttributeName, String stateAttributeName) {
		return StringUtils.hasText(request.getFirst(codeAttributeName)) && StringUtils.hasText(request.getFirst(stateAttributeName));
	}

	static boolean isAuthorizationResponseError(MultiValueMap<String, String> request, String errorAttributeName, String stateAttributeName) {
		return StringUtils.hasText(request.getFirst(errorAttributeName)) && StringUtils.hasText(request.getFirst(stateAttributeName));
	}

	static OAuth2AuthorizationResponse convert(MultiValueMap<String, String> request, String redirectUri, ClientRegistration clientRegistration) {
		ClientRegistration.ProviderDetails provider = clientRegistration.getProviderDetails();
		String code = request.getFirst(provider.getCodeAttributeName());
		String errorCode = request.getFirst(provider.getErrorAttributeName());
		String state = request.getFirst(provider.getStateAttributeName());

		if (StringUtils.hasText(code)) {
			return OAuth2AuthorizationResponse.success(code)
				.redirectUri(redirectUri)
				.state(state)
				.build();
		} else {
			String errorDescription = request.getFirst(provider.getErrorDescriptionAttributeName());
			String errorUri = request.getFirst(provider.getErrorUriAttributeName());
			return OAuth2AuthorizationResponse.error(errorCode)
				.redirectUri(redirectUri)
				.errorDescription(errorDescription)
				.errorUri(errorUri)
				.state(state)
				.build();
		}
	}
}
