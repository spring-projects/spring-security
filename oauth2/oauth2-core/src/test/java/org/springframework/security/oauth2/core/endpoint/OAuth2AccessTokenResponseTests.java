/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.core.endpoint;

import org.junit.Test;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.util.Collections;

/**
 * Tests {@link OAuth2AccessTokenResponse}
 *
 * @author Luander Ribeiro
 */
public class OAuth2AccessTokenResponseTests {

	private static final String TOKEN = "token";
	private static final long INVALID_EXPIRES_IN = -1L;
	private static final long EXPIRES_IN = System.currentTimeMillis();

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenTokenValueIsNullThenThrowIllegalArgumentException() {
		OAuth2AccessTokenResponse.withToken(null)
			.expiresIn(EXPIRES_IN)
			.additionalParameters(Collections.emptyMap())
			.scopes(Collections.emptySet())
			.tokenType(OAuth2AccessToken.TokenType.BEARER)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenExpiresInIsNegativeThenThrowIllegalArgumentException() {
		OAuth2AccessTokenResponse.withToken(TOKEN)
			.expiresIn(INVALID_EXPIRES_IN)
			.additionalParameters(Collections.emptyMap())
			.scopes(Collections.emptySet())
			.tokenType(OAuth2AccessToken.TokenType.BEARER)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenTokenTypeIsInvalidThenThrowIllegalArgumentException() {
		OAuth2AccessTokenResponse.withToken(TOKEN)
			.expiresIn(EXPIRES_IN)
			.additionalParameters(Collections.emptyMap())
			.tokenType(null)
			.build();
	}

	@Test(expected = IllegalArgumentException.class)
	public void buildWhenTokenTypeNotSetThenThrowIllegalArgumentException() {
		OAuth2AccessTokenResponse.withToken(TOKEN)
			.expiresIn(EXPIRES_IN)
			.additionalParameters(Collections.emptyMap())
			.build();
	}
}
