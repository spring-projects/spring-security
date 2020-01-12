/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.oauth2.core.http.converter;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.StringUtils;

import java.util.*;

/**
 * A {@link Converter} that converts the provided
 * OAuth 2.0 Access Token Response parameters to an {@link OAuth2AccessTokenResponse}.
 *
 * @author Joe Grandja
 * @author Nikita Konev
 * @since 5.3
 */
public final class OAuth2AccessTokenResponseConverter implements Converter<Map<String, String>, OAuth2AccessTokenResponse> {
	private static final Set<String> TOKEN_RESPONSE_PARAMETER_NAMES = new HashSet<>(Arrays.asList(
			OAuth2ParameterNames.ACCESS_TOKEN,
			OAuth2ParameterNames.EXPIRES_IN,
			OAuth2ParameterNames.REFRESH_TOKEN,
			OAuth2ParameterNames.SCOPE,
			OAuth2ParameterNames.TOKEN_TYPE
	));

	@Override
	public OAuth2AccessTokenResponse convert(Map<String, String> tokenResponseParameters) {
		String accessToken = tokenResponseParameters.get(OAuth2ParameterNames.ACCESS_TOKEN);

		OAuth2AccessToken.TokenType accessTokenType = null;
		if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(
				tokenResponseParameters.get(OAuth2ParameterNames.TOKEN_TYPE))) {
			accessTokenType = OAuth2AccessToken.TokenType.BEARER;
		}

		long expiresIn = 0;
		if (tokenResponseParameters.containsKey(OAuth2ParameterNames.EXPIRES_IN)) {
			try {
				expiresIn = Long.parseLong(tokenResponseParameters.get(OAuth2ParameterNames.EXPIRES_IN));
			} catch (NumberFormatException ex) {
			}
		}

		Set<String> scopes = Collections.emptySet();
		if (tokenResponseParameters.containsKey(OAuth2ParameterNames.SCOPE)) {
			String scope = tokenResponseParameters.get(OAuth2ParameterNames.SCOPE);
			scopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
		}

		String refreshToken = tokenResponseParameters.get(OAuth2ParameterNames.REFRESH_TOKEN);

		Map<String, Object> additionalParameters = new LinkedHashMap<>();
		for (Map.Entry<String, String> entry : tokenResponseParameters.entrySet()) {
			if (!TOKEN_RESPONSE_PARAMETER_NAMES.contains(entry.getKey())) {
				additionalParameters.put(entry.getKey(), entry.getValue());
			}
		}

		return OAuth2AccessTokenResponse.withToken(accessToken)
				.tokenType(accessTokenType)
				.expiresIn(expiresIn)
				.scopes(scopes)
				.refreshToken(refreshToken)
				.additionalParameters(additionalParameters)
				.build();
	}
}
