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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.jspecify.annotations.Nullable;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthenticationContext} that holds an
 * {@link OAuth2RefreshTokenAuthenticationToken} and additional information and is used
 * when validating the OAuth 2.0 Refresh Token Grant Request.
 * <p>
 * This context provides access to the current {@link OAuth2Authorization},
 * {@link OAuth2ClientAuthenticationToken}, and optionally a DPoP {@link Jwt} proof.
 * </p>
 *
 * @author Andrey Litvitski
 * @since 7.0.0
 * @see OAuth2AuthenticationContext
 * @see OAuth2RefreshTokenAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
public final class OAuth2RefreshTokenAuthenticationContext implements OAuth2AuthenticationContext {

	private final Map<Object, Object> context;

	private OAuth2RefreshTokenAuthenticationContext(Map<Object, Object> context) {
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

	public OAuth2Authorization getAuthorization() {
		return get(OAuth2Authorization.class);
	}

	public OAuth2ClientAuthenticationToken getClientPrincipal() {
		return get(OAuth2ClientAuthenticationToken.class);
	}

	@Nullable public Jwt getDPoPProof() {
		return get(Jwt.class);
	}

	public static Builder with(OAuth2RefreshTokenAuthenticationToken authentication) {
		return new Builder(authentication);
	}

	public static final class Builder extends AbstractBuilder<OAuth2RefreshTokenAuthenticationContext, Builder> {

		private Builder(OAuth2RefreshTokenAuthenticationToken authentication) {
			super(authentication);
		}

		public Builder authorization(OAuth2Authorization authorization) {
			return put(OAuth2Authorization.class, authorization);
		}

		public Builder clientPrincipal(OAuth2ClientAuthenticationToken clientPrincipal) {
			return put(OAuth2ClientAuthenticationToken.class, clientPrincipal);
		}

		public Builder dPoPProof(@Nullable Jwt dPoPProof) {
			if (dPoPProof != null) {
				put(Jwt.class, dPoPProof);
			}
			return this;
		}

		@Override
		public OAuth2RefreshTokenAuthenticationContext build() {
			Assert.notNull(get(OAuth2Authorization.class), "authorization cannot be null");
			Assert.notNull(get(OAuth2ClientAuthenticationToken.class), "clientPrincipal cannot be null");
			return new OAuth2RefreshTokenAuthenticationContext(getContext());
		}

	}

}
