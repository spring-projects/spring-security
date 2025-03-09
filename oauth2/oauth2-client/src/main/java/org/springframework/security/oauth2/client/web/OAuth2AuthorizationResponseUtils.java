/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.client.web;

import java.util.*;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;


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

	static boolean isAuthorizationResponse(MultiValueMap<String, String> request) {
		return isAuthorizationResponseSuccess(request) || isAuthorizationResponseError(request);
	}

	static boolean isAuthorizationResponseSuccess(MultiValueMap<String, String> request) {
		return StringUtils.hasText(request.getFirst(OAuth2ParameterNames.CODE))
				&& StringUtils.hasText(request.getFirst(OAuth2ParameterNames.STATE));
	}

	static boolean isAuthorizationResponseError(MultiValueMap<String, String> request) {
		return StringUtils.hasText(request.getFirst(OAuth2ParameterNames.ERROR))
				&& StringUtils.hasText(request.getFirst(OAuth2ParameterNames.STATE));
	}

	private static final Set<String> AUTHORIZATION_RESPONSE_PARAMETER_NAMES = new HashSet<>(
			Arrays.asList(
					OAuth2ParameterNames.CODE,
					OAuth2ParameterNames.ERROR,
					OAuth2ParameterNames.STATE,
					OAuth2ParameterNames.ERROR_DESCRIPTION,
					OAuth2ParameterNames.REDIRECT_URI,
					OAuth2ParameterNames.ERROR_URI));

	static OAuth2AuthorizationResponse convert(MultiValueMap<String, String> parameters, String redirectUri) {
		String code = parameters.getFirst(OAuth2ParameterNames.CODE);
		String errorCode = parameters.getFirst(OAuth2ParameterNames.ERROR);
		String state = parameters.getFirst(OAuth2ParameterNames.STATE);
		if (StringUtils.hasText(code)) {
			Map<String, Object> additionalParameters = new LinkedHashMap<>();
			parameters.forEach((key, value) -> {
				if (!AUTHORIZATION_RESPONSE_PARAMETER_NAMES.contains(key)) {
					additionalParameters.put(
							key,
							value);
				}
			});
			return OAuth2AuthorizationResponse.success(code)
					.redirectUri(redirectUri)
					.state(state)
					.additionalParameters(additionalParameters)
					.build();
		}
		String errorDescription = parameters.getFirst(OAuth2ParameterNames.ERROR_DESCRIPTION);
		String errorUri = parameters.getFirst(OAuth2ParameterNames.ERROR_URI);
		// @formatter:off
		return OAuth2AuthorizationResponse.error(errorCode)
				.redirectUri(redirectUri)
				.errorDescription(errorDescription)
				.errorUri(errorUri)
				.state(state)
				.build();
		// @formatter:on
	}

}
