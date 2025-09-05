/*
 * Copyright 2004-present the original author or authors.
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

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link DelegatingOAuth2TokenGenerator}.
 *
 * @author Joe Grandja
 */
public class DelegatingOAuth2TokenGeneratorTests {

	@Test
	@SuppressWarnings("unchecked")
	public void constructorWhenTokenGeneratorsEmptyThenThrowIllegalArgumentException() {
		OAuth2TokenGenerator<OAuth2Token>[] tokenGenerators = new OAuth2TokenGenerator[0];
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new DelegatingOAuth2TokenGenerator(tokenGenerators))
			.withMessage("tokenGenerators cannot be empty");
	}

	@Test
	public void constructorWhenTokenGeneratorsNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new DelegatingOAuth2TokenGenerator(null, null))
			.withMessage("tokenGenerator cannot be null");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void generateWhenTokenGeneratorSupportedThenReturnToken() {
		OAuth2TokenGenerator<OAuth2Token> tokenGenerator1 = mock(OAuth2TokenGenerator.class);
		OAuth2TokenGenerator<OAuth2Token> tokenGenerator2 = mock(OAuth2TokenGenerator.class);
		OAuth2TokenGenerator<OAuth2Token> tokenGenerator3 = mock(OAuth2TokenGenerator.class);

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "access-token",
				Instant.now(), Instant.now().plusSeconds(300));
		given(tokenGenerator3.generate(any())).willReturn(accessToken);

		DelegatingOAuth2TokenGenerator delegatingTokenGenerator = new DelegatingOAuth2TokenGenerator(tokenGenerator1,
				tokenGenerator2, tokenGenerator3);

		OAuth2Token token = delegatingTokenGenerator.generate(DefaultOAuth2TokenContext.builder().build());
		assertThat(token).isEqualTo(accessToken);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void generateWhenTokenGeneratorNotSupportedThenReturnNull() {
		OAuth2TokenGenerator<OAuth2Token> tokenGenerator1 = mock(OAuth2TokenGenerator.class);
		OAuth2TokenGenerator<OAuth2Token> tokenGenerator2 = mock(OAuth2TokenGenerator.class);
		OAuth2TokenGenerator<OAuth2Token> tokenGenerator3 = mock(OAuth2TokenGenerator.class);

		DelegatingOAuth2TokenGenerator delegatingTokenGenerator = new DelegatingOAuth2TokenGenerator(tokenGenerator1,
				tokenGenerator2, tokenGenerator3);

		OAuth2Token token = delegatingTokenGenerator.generate(DefaultOAuth2TokenContext.builder().build());
		assertThat(token).isNull();
	}

}
