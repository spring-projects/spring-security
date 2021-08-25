/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.core.endpoint;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.util.StringUtils;

/**
 * A {@link Converter} that converts the provided OAuth 2.0 Access Token Response
 * parameters to an {@link OAuth2AccessTokenResponse}.
 *
 * @author Steve Riesenberg
 * @since 5.6
 */
public final class DefaultMapOAuth2AccessTokenResponseConverter
		implements Converter<Map<String, Object>, OAuth2AccessTokenResponse> {

	private static final Set<String> TOKEN_RESPONSE_PARAMETER_NAMES = new HashSet<>(
			Arrays.asList(OAuth2ParameterNames.ACCESS_TOKEN, OAuth2ParameterNames.EXPIRES_IN,
					OAuth2ParameterNames.REFRESH_TOKEN, OAuth2ParameterNames.SCOPE, OAuth2ParameterNames.TOKEN_TYPE));

	@Override
	public OAuth2AccessTokenResponse convert(Map<String, Object> source) {
		String accessToken = getParameterValue(source, OAuth2ParameterNames.ACCESS_TOKEN);
		OAuth2AccessToken.TokenType accessTokenType = getAccessTokenType(source);
		long expiresIn = getExpiresIn(source);
		Set<String> scopes = getScopes(source);
		String refreshToken = getParameterValue(source, OAuth2ParameterNames.REFRESH_TOKEN);
		Map<String, Object> additionalParameters = new LinkedHashMap<>();
		for (Map.Entry<String, Object> entry : source.entrySet()) {
			if (!TOKEN_RESPONSE_PARAMETER_NAMES.contains(entry.getKey())) {
				additionalParameters.put(entry.getKey(), entry.getValue());
			}
		}
		// @formatter:off
		return OAuth2AccessTokenResponse.withToken(accessToken)
				.tokenType(accessTokenType)
				.expiresIn(expiresIn)
				.scopes(scopes)
				.refreshToken(refreshToken)
				.additionalParameters(additionalParameters)
				.build();
		// @formatter:on
	}

	private static OAuth2AccessToken.TokenType getAccessTokenType(Map<String, Object> tokenResponseParameters) {
		if (OAuth2AccessToken.TokenType.BEARER.getValue()
				.equalsIgnoreCase(getParameterValue(tokenResponseParameters, OAuth2ParameterNames.TOKEN_TYPE))) {
			return OAuth2AccessToken.TokenType.BEARER;
		}
		return null;
	}

	private static long getExpiresIn(Map<String, Object> tokenResponseParameters) {
		return getParameterValue(tokenResponseParameters, OAuth2ParameterNames.EXPIRES_IN, 0L);
	}

	private static Set<String> getScopes(Map<String, Object> tokenResponseParameters) {
		if (tokenResponseParameters.containsKey(OAuth2ParameterNames.SCOPE)) {
			String scope = getParameterValue(tokenResponseParameters, OAuth2ParameterNames.SCOPE);
			return new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
		}
		return Collections.emptySet();
	}

	private static String getParameterValue(Map<String, Object> tokenResponseParameters, String parameterName) {
		Object obj = tokenResponseParameters.get(parameterName);
		return (obj != null) ? obj.toString() : null;
	}

	private static long getParameterValue(Map<String, Object> tokenResponseParameters, String parameterName,
			long defaultValue) {
		long parameterValue = defaultValue;

		Object obj = tokenResponseParameters.get(parameterName);
		if (obj != null) {
			// Final classes Long and Integer do not need to be coerced
			if (obj.getClass() == Long.class) {
				parameterValue = (Long) obj;
			}
			else if (obj.getClass() == Integer.class) {
				parameterValue = (Integer) obj;
			}
			else {
				// Attempt to coerce to a long (typically from a String)
				try {
					parameterValue = Long.parseLong(obj.toString());
				}
				catch (NumberFormatException ignored) {
				}
			}
		}

		return parameterValue;
	}

}
