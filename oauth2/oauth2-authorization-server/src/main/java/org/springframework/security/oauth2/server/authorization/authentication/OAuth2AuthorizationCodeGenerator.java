/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.authentication;

import java.time.Instant;
import java.util.Base64;

import org.springframework.lang.Nullable;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * An {@link OAuth2TokenGenerator} that generates an {@link OAuth2AuthorizationCode}.
 *
 * @author Joe Grandja
 * @since 0.4.0
 * @see OAuth2TokenGenerator
 * @see OAuth2AuthorizationCode
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
 * @see OAuth2AuthorizationConsentAuthenticationProvider
 */
final class OAuth2AuthorizationCodeGenerator implements OAuth2TokenGenerator<OAuth2AuthorizationCode> {

	private final StringKeyGenerator authorizationCodeGenerator = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 96);

	@Nullable
	@Override
	public OAuth2AuthorizationCode generate(OAuth2TokenContext context) {
		if (context.getTokenType() == null || !OAuth2ParameterNames.CODE.equals(context.getTokenType().getValue())) {
			return null;
		}
		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt
			.plus(context.getRegisteredClient().getTokenSettings().getAuthorizationCodeTimeToLive());
		return new OAuth2AuthorizationCode(this.authorizationCodeGenerator.generateKey(), issuedAt, expiresAt);
	}

}
