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
package org.springframework.security.oauth2.server.authorization.token;

import java.time.Instant;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.TestRegisteredClients;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2RefreshTokenGenerator}.
 *
 * @author Joe Grandja
 */
public class OAuth2RefreshTokenGeneratorTests {

	private final OAuth2RefreshTokenGenerator tokenGenerator = new OAuth2RefreshTokenGenerator();

	@Test
	public void generateWhenUnsupportedTokenTypeThenReturnNull() {
		// @formatter:off
		OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
				.tokenType(OAuth2TokenType.ACCESS_TOKEN)
				.build();
		// @formatter:on

		assertThat(this.tokenGenerator.generate(tokenContext)).isNull();
	}

	@Test
	public void generateWhenRefreshTokenTypeThenReturnRefreshToken() {
		RegisteredClient registeredClient = TestRegisteredClients.registeredClient().build();

		// @formatter:off
		OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.tokenType(OAuth2TokenType.REFRESH_TOKEN)
				.build();
		// @formatter:on

		OAuth2RefreshToken refreshToken = this.tokenGenerator.generate(tokenContext);
		assertThat(refreshToken).isNotNull();

		Instant issuedAt = Instant.now();
		Instant expiresAt = issuedAt
			.plus(tokenContext.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
		assertThat(refreshToken.getIssuedAt()).isBetween(issuedAt.minusSeconds(1), issuedAt.plusSeconds(1));
		assertThat(refreshToken.getExpiresAt()).isBetween(expiresAt.minusSeconds(1), expiresAt.plusSeconds(1));
	}

}
