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
package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationContext;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthenticationContext} that holds an
 * {@link OidcUserInfoAuthenticationToken} and additional information and is used when
 * mapping claims to an instance of {@link OidcUserInfo}.
 *
 * @author Joe Grandja
 * @since 0.2.1
 * @see OAuth2AuthenticationContext
 * @see OidcUserInfo
 * @see OidcUserInfoAuthenticationProvider#setUserInfoMapper(Function)
 */
public final class OidcUserInfoAuthenticationContext implements OAuth2AuthenticationContext {

	private final Map<Object, Object> context;

	private OidcUserInfoAuthenticationContext(Map<Object, Object> context) {
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
	 * Returns the {@link OAuth2AccessToken OAuth 2.0 Access Token}.
	 * @return the {@link OAuth2AccessToken}
	 */
	public OAuth2AccessToken getAccessToken() {
		return get(OAuth2AccessToken.class);
	}

	/**
	 * Returns the {@link OAuth2Authorization authorization}.
	 * @return the {@link OAuth2Authorization}
	 */
	public OAuth2Authorization getAuthorization() {
		return get(OAuth2Authorization.class);
	}

	/**
	 * Constructs a new {@link Builder} with the provided
	 * {@link OidcUserInfoAuthenticationToken}.
	 * @param authentication the {@link OidcUserInfoAuthenticationToken}
	 * @return the {@link Builder}
	 */
	public static Builder with(OidcUserInfoAuthenticationToken authentication) {
		return new Builder(authentication);
	}

	/**
	 * A builder for {@link OidcUserInfoAuthenticationContext}.
	 */
	public static final class Builder extends AbstractBuilder<OidcUserInfoAuthenticationContext, Builder> {

		private Builder(OidcUserInfoAuthenticationToken authentication) {
			super(authentication);
		}

		/**
		 * Sets the {@link OAuth2AccessToken OAuth 2.0 Access Token}.
		 * @param accessToken the {@link OAuth2AccessToken}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder accessToken(OAuth2AccessToken accessToken) {
			return put(OAuth2AccessToken.class, accessToken);
		}

		/**
		 * Sets the {@link OAuth2Authorization authorization}.
		 * @param authorization the {@link OAuth2Authorization}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder authorization(OAuth2Authorization authorization) {
			return put(OAuth2Authorization.class, authorization);
		}

		/**
		 * Builds a new {@link OidcUserInfoAuthenticationContext}.
		 * @return the {@link OidcUserInfoAuthenticationContext}
		 */
		@Override
		public OidcUserInfoAuthenticationContext build() {
			Assert.notNull(get(OAuth2AccessToken.class), "accessToken cannot be null");
			Assert.notNull(get(OAuth2Authorization.class), "authorization cannot be null");
			return new OidcUserInfoAuthenticationContext(getContext());
		}

	}

}
