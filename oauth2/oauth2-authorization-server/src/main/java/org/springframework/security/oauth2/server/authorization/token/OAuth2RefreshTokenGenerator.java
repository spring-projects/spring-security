/*
 * Copyright 2020-2023 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.token;

import java.time.Instant;
import java.util.Base64;

import org.springframework.lang.Nullable;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

/**
 * An {@link OAuth2TokenGenerator} that generates an {@link OAuth2RefreshToken}.
 *
 * @author Joe Grandja
 * @since 0.2.3
 * @see OAuth2TokenGenerator
 * @see OAuth2RefreshToken
 */
public final class OAuth2RefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

	private final StringKeyGenerator refreshTokenGenerator = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 96);

	@Nullable
	@Override
	public OAuth2RefreshToken generate(OAuth2TokenContext context) {
		if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
			return null;
		}
		if (isPublicClientForAuthorizationCodeGrant(context)) {
			// Do not issue refresh token to public client
			return null;
		}

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
		return new OAuth2RefreshToken(this.refreshTokenGenerator.generateKey(), issuedAt, expiresAt);
	}

	private static boolean isPublicClientForAuthorizationCodeGrant(OAuth2TokenContext context) {
		// @formatter:off
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(context.getAuthorizationGrantType()) &&
				(context.getAuthorizationGrant().getPrincipal() instanceof OAuth2ClientAuthenticationToken clientPrincipal)) {
			return clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE);
		}
		// @formatter:on
		return false;
	}

}
