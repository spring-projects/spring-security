/*
 * Copyright 2020-2024 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;

/**
 * Utility methods for the OpenID Connect 1.0 {@link AuthenticationProvider}'s.
 *
 * @author Joe Grandja
 * @since 0.1.1
 */
final class OidcAuthenticationProviderUtils {

	private OidcAuthenticationProviderUtils() {
	}

	static <T extends OAuth2Token> OAuth2AccessToken accessToken(OAuth2Authorization.Builder builder, T token,
			OAuth2TokenContext accessTokenContext) {

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token.getTokenValue(),
				token.getIssuedAt(), token.getExpiresAt(), accessTokenContext.getAuthorizedScopes());
		OAuth2TokenFormat accessTokenFormat = accessTokenContext.getRegisteredClient()
			.getTokenSettings()
			.getAccessTokenFormat();
		builder.token(accessToken, (metadata) -> {
			if (token instanceof ClaimAccessor claimAccessor) {
				metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, claimAccessor.getClaims());
			}
			metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
			metadata.put(OAuth2TokenFormat.class.getName(), accessTokenFormat.getValue());
		});

		return accessToken;
	}

}
