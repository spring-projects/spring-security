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

package org.springframework.security.oauth2.core.endpoint;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;

/**
 * @author Rob Winch
 * @since 5.1
 */
public final class TestOAuth2AccessTokenResponses {

	private TestOAuth2AccessTokenResponses() {
	}

	public static OAuth2AccessTokenResponse.Builder accessTokenResponse() {
		// @formatter:off
		return OAuth2AccessTokenResponse
				.withToken("token")
				.tokenType(OAuth2AccessToken.TokenType.BEARER);
		// @formatter:on
	}

	public static OAuth2AccessTokenResponse.Builder oidcAccessTokenResponse() {
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OidcParameterNames.ID_TOKEN, "id-token");
		return accessTokenResponse().scopes(Collections.singleton(OidcScopes.OPENID))
				.additionalParameters(additionalParameters);
	}

}
