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
package org.springframework.security.oauth2.core.protocol;

import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.util.Assert;

import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * @author Joe Grandja
 */
public class TokenResponseAttributes {
	private final String accessToken;
	private final AccessToken.TokenType accessTokenType;
	private final Duration expiresIn;
	private final Set<String> scopes;
	private final String refreshToken;
	private final Map<String,String> additionalParameters;

	public TokenResponseAttributes(String accessToken, AccessToken.TokenType accessTokenType, long expiresIn) {
		this(accessToken, accessTokenType, expiresIn, Collections.emptySet());
	}

	public TokenResponseAttributes(String accessToken, AccessToken.TokenType accessTokenType, long expiresIn, Set<String> scopes) {
		this(accessToken, accessTokenType, expiresIn, scopes, null);
	}

	public TokenResponseAttributes(String accessToken, AccessToken.TokenType accessTokenType, long expiresIn,
									Set<String> scopes, String refreshToken) {

		this(accessToken, accessTokenType, expiresIn, scopes, refreshToken, Collections.emptyMap());
	}

	public TokenResponseAttributes(String accessToken, AccessToken.TokenType accessTokenType, long expiresIn,
									Set<String> scopes, String refreshToken, Map<String,String> additionalParameters) {

		Assert.notNull(accessToken, "accessToken cannot be null");
		this.accessToken = accessToken;

		Assert.notNull(accessTokenType, "accessTokenType cannot be null");
		this.accessTokenType = accessTokenType;

		Assert.isTrue(expiresIn >= 0, "expiresIn must be a positive number");
		this.expiresIn = Duration.ofSeconds(expiresIn);

		this.scopes = Collections.unmodifiableSet(scopes != null ? scopes : Collections.emptySet());
		this.refreshToken = refreshToken;
		this.additionalParameters = Collections.unmodifiableMap(additionalParameters != null ?
				additionalParameters : Collections.emptyMap());
	}

	public final String getAccessToken() {
		return this.accessToken;
	}

	public final AccessToken.TokenType getAccessTokenType() {
		return this.accessTokenType;
	}

	public final Duration getExpiresIn() {
		return this.expiresIn;
	}

	public final Set<String> getScopes() {
		return this.scopes;
	}

	public final String getRefreshToken() {
		return this.refreshToken;
	}

	public final Map<String, String> getAdditionalParameters() {
		return this.additionalParameters;
	}
}
