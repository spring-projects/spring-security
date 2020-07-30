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

import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * A representation of an OAuth 2.0 Access Token Response.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see OAuth2AccessToken
 * @see OAuth2RefreshToken
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-5.1">Section
 * 5.1 Access Token Response</a>
 */
public final class OAuth2AccessTokenResponse {

	private OAuth2AccessToken accessToken;

	private OAuth2RefreshToken refreshToken;

	private Map<String, Object> additionalParameters;

	private OAuth2AccessTokenResponse() {
	}

	/**
	 * Returns the {@link OAuth2AccessToken Access Token}.
	 * @return the {@link OAuth2AccessToken}
	 */
	public OAuth2AccessToken getAccessToken() {
		return this.accessToken;
	}

	/**
	 * Returns the {@link OAuth2RefreshToken Refresh Token}.
	 * @return the {@link OAuth2RefreshToken}
	 * @since 5.1
	 */
	public @Nullable OAuth2RefreshToken getRefreshToken() {
		return this.refreshToken;
	}

	/**
	 * Returns the additional parameters returned in the response.
	 * @return a {@code Map} of the additional parameters returned in the response, may be
	 * empty.
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

	/**
	 * Returns a new {@link Builder}, initialized with the provided access token value.
	 * @param tokenValue the value of the access token
	 * @return the {@link Builder}
	 */
	public static Builder withToken(String tokenValue) {
		return new Builder(tokenValue);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the provided response.
	 * @param response the response to initialize the builder with
	 * @return the {@link Builder}
	 */
	public static Builder withResponse(OAuth2AccessTokenResponse response) {
		return new Builder(response);
	}

	/**
	 * A builder for {@link OAuth2AccessTokenResponse}.
	 */
	public static final class Builder {

		private String tokenValue;

		private OAuth2AccessToken.TokenType tokenType;

		private Instant issuedAt;

		private Instant expiresAt;

		private long expiresIn;

		private Set<String> scopes;

		private String refreshToken;

		private Map<String, Object> additionalParameters;

		private Builder(OAuth2AccessTokenResponse response) {
			OAuth2AccessToken accessToken = response.getAccessToken();
			this.tokenValue = accessToken.getTokenValue();
			this.tokenType = accessToken.getTokenType();
			this.issuedAt = accessToken.getIssuedAt();
			this.expiresAt = accessToken.getExpiresAt();
			this.scopes = accessToken.getScopes();
			this.refreshToken = (response.getRefreshToken() != null) ? response.getRefreshToken().getTokenValue()
					: null;
			this.additionalParameters = response.getAdditionalParameters();
		}

		private Builder(String tokenValue) {
			this.tokenValue = tokenValue;
		}

		/**
		 * Sets the {@link OAuth2AccessToken.TokenType token type}.
		 * @param tokenType the type of token issued
		 * @return the {@link Builder}
		 */
		public Builder tokenType(OAuth2AccessToken.TokenType tokenType) {
			this.tokenType = tokenType;
			return this;
		}

		/**
		 * Sets the lifetime (in seconds) of the access token.
		 * @param expiresIn the lifetime of the access token, in seconds.
		 * @return the {@link Builder}
		 */
		public Builder expiresIn(long expiresIn) {
			this.expiresIn = expiresIn;
			this.expiresAt = null;
			return this;
		}

		/**
		 * Sets the scope(s) associated to the access token.
		 * @param scopes the scope(s) associated to the access token.
		 * @return the {@link Builder}
		 */
		public Builder scopes(Set<String> scopes) {
			this.scopes = scopes;
			return this;
		}

		/**
		 * Sets the refresh token associated to the access token.
		 * @param refreshToken the refresh token associated to the access token.
		 * @return the {@link Builder}
		 */
		public Builder refreshToken(String refreshToken) {
			this.refreshToken = refreshToken;
			return this;
		}

		/**
		 * Sets the additional parameters returned in the response.
		 * @param additionalParameters the additional parameters returned in the response
		 * @return the {@link Builder}
		 */
		public Builder additionalParameters(Map<String, Object> additionalParameters) {
			this.additionalParameters = additionalParameters;
			return this;
		}

		/**
		 * Builds a new {@link OAuth2AccessTokenResponse}.
		 * @return a {@link OAuth2AccessTokenResponse}
		 */
		public OAuth2AccessTokenResponse build() {
			Instant issuedAt = getIssuedAt();
			Instant expiresAt = getExpiresAt();

			OAuth2AccessTokenResponse accessTokenResponse = new OAuth2AccessTokenResponse();
			accessTokenResponse.accessToken = new OAuth2AccessToken(this.tokenType, this.tokenValue, issuedAt,
					expiresAt, this.scopes);
			if (StringUtils.hasText(this.refreshToken)) {
				accessTokenResponse.refreshToken = new OAuth2RefreshToken(this.refreshToken, issuedAt);
			}
			accessTokenResponse.additionalParameters = Collections
					.unmodifiableMap(CollectionUtils.isEmpty(this.additionalParameters) ? Collections.emptyMap()
							: this.additionalParameters);
			return accessTokenResponse;
		}

		private Instant getIssuedAt() {
			if (this.issuedAt == null) {
				this.issuedAt = Instant.now();
			}
			return this.issuedAt;
		}

		/**
		 * expires_in is RECOMMENDED, as per spec
		 * https://tools.ietf.org/html/rfc6749#section-5.1 Therefore, expires_in may not
		 * be returned in the Access Token response which would result in the default
		 * value of 0. For these instances, default the expiresAt to +1 second from
		 * issuedAt time.
		 * @return
		 */
		private Instant getExpiresAt() {
			if (this.expiresAt == null) {
				Instant issuedAt = getIssuedAt();
				this.expiresAt = (this.expiresIn > 0) ? issuedAt.plusSeconds(this.expiresIn) : issuedAt.plusSeconds(1);
			}
			return this.expiresAt;
		}

	}

}
