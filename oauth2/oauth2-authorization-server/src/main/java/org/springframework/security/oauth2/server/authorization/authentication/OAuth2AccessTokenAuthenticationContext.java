/*
 * Copyright 2020-2025 the original author or authors.
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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AccessTokenResponseAuthenticationSuccessHandler;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthenticationContext} that holds an
 * {@link OAuth2AccessTokenAuthenticationToken} and additional information and is used
 * when customizing the {@link OAuth2AccessTokenResponse}.
 *
 * @author Dmitriy Dubson
 * @since 1.3
 * @see OAuth2AuthenticationContext
 * @see OAuth2AccessTokenAuthenticationToken
 * @see OAuth2AccessTokenResponse
 * @see OAuth2AccessTokenResponseAuthenticationSuccessHandler#setAccessTokenResponseCustomizer(Consumer)
 */
public final class OAuth2AccessTokenAuthenticationContext implements OAuth2AuthenticationContext {

	private final Map<Object, Object> context;

	private OAuth2AccessTokenAuthenticationContext(Map<Object, Object> context) {
		this.context = Collections.unmodifiableMap(new HashMap<>(context));
	}

	@SuppressWarnings("unchecked")
	@Nullable
	@Override
	public <V> V get(Object key) {
		return hasKey(key) ? (V) this.context.get(key) : null;
	}

	@Override
	public boolean hasKey(Object key) {
		Assert.notNull(key, "key cannot be null");
		return this.context.containsKey(key);
	}

	/**
	 * Returns the {@link OAuth2AccessTokenResponse.Builder access token response
	 * builder}.
	 * @return the {@link OAuth2AccessTokenResponse.Builder}
	 */
	public OAuth2AccessTokenResponse.Builder getAccessTokenResponse() {
		return get(OAuth2AccessTokenResponse.Builder.class);
	}

	/**
	 * Constructs a new {@link Builder} with the provided
	 * {@link OAuth2AccessTokenAuthenticationToken}.
	 * @param authentication the {@link OAuth2AccessTokenAuthenticationToken}
	 * @return the {@link Builder}
	 */
	public static Builder with(OAuth2AccessTokenAuthenticationToken authentication) {
		return new Builder(authentication);
	}

	/**
	 * A builder for {@link OAuth2AccessTokenAuthenticationContext}.
	 */
	public static final class Builder extends AbstractBuilder<OAuth2AccessTokenAuthenticationContext, Builder> {

		private Builder(OAuth2AccessTokenAuthenticationToken authentication) {
			super(authentication);
		}

		/**
		 * Sets the {@link OAuth2AccessTokenResponse.Builder access token response
		 * builder}.
		 * @param accessTokenResponse the {@link OAuth2AccessTokenResponse.Builder}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder accessTokenResponse(OAuth2AccessTokenResponse.Builder accessTokenResponse) {
			return put(OAuth2AccessTokenResponse.Builder.class, accessTokenResponse);
		}

		/**
		 * Builds a new {@link OAuth2AccessTokenAuthenticationContext}.
		 * @return the {@link OAuth2AccessTokenAuthenticationContext}
		 */
		@Override
		public OAuth2AccessTokenAuthenticationContext build() {
			Assert.notNull(get(OAuth2AccessTokenResponse.Builder.class), "accessTokenResponse cannot be null");
			return new OAuth2AccessTokenAuthenticationContext(getContext());
		}

	}

}
