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

import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * A representation of an <i>OAuth 2.0 Access Token Response</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AccessToken
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-5.1">Section 5.1 Access Token Response</a>
 */
public final class TokenResponse {
	private AccessToken accessToken;
	private Map<String,Object> additionalParameters;

	private TokenResponse() {
	}

	public String getTokenValue() {
		return this.accessToken.getTokenValue();
	}

	public AccessToken.TokenType getTokenType() {
		return this.accessToken.getTokenType();
	}

	public Instant getIssuedAt() {
		return this.accessToken.getIssuedAt();
	}

	public Instant getExpiresAt() {
		return this.accessToken.getExpiresAt();
	}

	public Set<String> getScope() {
		return this.accessToken.getScope();
	}

	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

	public static Builder withToken(String tokenValue) {
		return new Builder(tokenValue);
	}

	public static class Builder {
		private String tokenValue;
		private AccessToken.TokenType tokenType;
		private long expiresIn;
		private Set<String> scope;
		private Map<String,Object> additionalParameters;

		private Builder(String tokenValue) {
			this.tokenValue = tokenValue;
		}

		public Builder tokenType(AccessToken.TokenType tokenType) {
			this.tokenType = tokenType;
			return this;
		}

		public Builder expiresIn(long expiresIn) {
			this.expiresIn = expiresIn;
			return this;
		}

		public Builder scope(Set<String> scope) {
			this.scope = scope;
			return this;
		}

		public Builder additionalParameters(Map<String,Object> additionalParameters) {
			this.additionalParameters = additionalParameters;
			return this;
		}

		public TokenResponse build() {
			Assert.isTrue(this.expiresIn >= 0, "expiresIn must be a positive number");
			Instant issuedAt = Instant.now();
			TokenResponse tokenResponse = new TokenResponse();
			tokenResponse.accessToken = new AccessToken(this.tokenType, this.tokenValue, issuedAt,
				issuedAt.plusSeconds(this.expiresIn), this.scope);
			tokenResponse.additionalParameters = Collections.unmodifiableMap(
				CollectionUtils.isEmpty(this.additionalParameters) ? Collections.emptyMap() : this.additionalParameters);
			return tokenResponse;
		}
	}
}
