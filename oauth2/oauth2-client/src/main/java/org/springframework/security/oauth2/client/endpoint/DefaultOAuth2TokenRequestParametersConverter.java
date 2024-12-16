/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.oauth2.client.endpoint;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Default {@link Converter} used to convert an
 * {@link AbstractOAuth2AuthorizationGrantRequest} to the default {@link MultiValueMap
 * parameters} of an OAuth 2.0 Access Token Request.
 * <p>
 * This implementation provides grant-type specific parameters for the following grant
 * types:
 *
 * <ul>
 * <li>{@code authorization_code}</li>
 * <li>{@code refresh_token}</li>
 * <li>{@code client_credentials}</li>
 * <li>{@code password}</li>
 * <li>{@code urn:ietf:params:oauth:grant-type:jwt-bearer}</li>
 * <li>{@code urn:ietf:params:oauth:grant-type:token-exchange}</li>
 * </ul>
 *
 * In addition, the following default parameters are provided:
 *
 * <ul>
 * <li>{@code grant_type} - always provided</li>
 * <li>{@code client_id} - provided unless the {@code clientAuthenticationMethod} is
 * {@code client_secret_basic}</li>
 * <li>{@code client_secret} - provided when the {@code clientAuthenticationMethod} is
 * {@code client_secret_post}</li>
 * </ul>
 *
 * @param <T> type of grant request
 * @author Steve Riesenberg
 * @since 6.4
 * @see AbstractWebClientReactiveOAuth2AccessTokenResponseClient
 * @see AbstractRestClientOAuth2AccessTokenResponseClient
 */
public final class DefaultOAuth2TokenRequestParametersConverter<T extends AbstractOAuth2AuthorizationGrantRequest>
		implements Converter<T, MultiValueMap<String, String>> {

	private final Converter<T, MultiValueMap<String, String>> defaultParametersConverter = createDefaultParametersConverter();

	@Override
	public MultiValueMap<String, String> convert(T grantRequest) {
		ClientRegistration clientRegistration = grantRequest.getClientRegistration();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		parameters.set(OAuth2ParameterNames.GRANT_TYPE, grantRequest.getGrantType().getValue());
		if (!ClientAuthenticationMethod.CLIENT_SECRET_BASIC
			.equals(clientRegistration.getClientAuthenticationMethod())) {
			parameters.set(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
		}
		if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(clientRegistration.getClientAuthenticationMethod())) {
			parameters.set(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
		}

		MultiValueMap<String, String> defaultParameters = this.defaultParametersConverter.convert(grantRequest);
		if (defaultParameters != null) {
			parameters.addAll(defaultParameters);
		}

		return parameters;
	}

	private static <T extends AbstractOAuth2AuthorizationGrantRequest> Converter<T, MultiValueMap<String, String>> createDefaultParametersConverter() {
		return (grantRequest) -> {
			if (grantRequest instanceof OAuth2AuthorizationCodeGrantRequest authorizationCodeGrantRequest) {
				return OAuth2AuthorizationCodeGrantRequest.defaultParameters(authorizationCodeGrantRequest);
			}
			else if (grantRequest instanceof OAuth2ClientCredentialsGrantRequest clientCredentialsGrantRequest) {
				return OAuth2ClientCredentialsGrantRequest.defaultParameters(clientCredentialsGrantRequest);
			}
			else if (grantRequest instanceof OAuth2RefreshTokenGrantRequest refreshTokenGrantRequest) {
				return OAuth2RefreshTokenGrantRequest.defaultParameters(refreshTokenGrantRequest);
			}
			else if (grantRequest instanceof OAuth2PasswordGrantRequest passwordGrantRequest) {
				return OAuth2PasswordGrantRequest.defaultParameters(passwordGrantRequest);
			}
			else if (grantRequest instanceof JwtBearerGrantRequest jwtBearerGrantRequest) {
				return JwtBearerGrantRequest.defaultParameters(jwtBearerGrantRequest);
			}
			else if (grantRequest instanceof TokenExchangeGrantRequest tokenExchangeGrantRequest) {
				return TokenExchangeGrantRequest.defaultParameters(tokenExchangeGrantRequest);
			}
			return null;
		};
	}

}
