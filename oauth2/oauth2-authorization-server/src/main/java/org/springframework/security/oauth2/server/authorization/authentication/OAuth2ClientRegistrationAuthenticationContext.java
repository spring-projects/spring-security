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

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthenticationContext} that holds an
 * {@link OAuth2ClientRegistrationAuthenticationToken} and additional information and is
 * used when validating the OAuth 2.0 Client Registration Request parameters.
 *
 * @author addcontent
 * @since 7.0
 * @see OAuth2AuthenticationContext
 * @see OAuth2ClientRegistrationAuthenticationToken
 * @see OAuth2ClientRegistrationAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
public final class OAuth2ClientRegistrationAuthenticationContext implements OAuth2AuthenticationContext {

	private final Map<Object, Object> context;

	private OAuth2ClientRegistrationAuthenticationContext(Map<Object, Object> context) {
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
	 * Constructs a new {@link Builder} with the provided
	 * {@link OAuth2ClientRegistrationAuthenticationToken}.
	 * @param authentication the {@link OAuth2ClientRegistrationAuthenticationToken}
	 * @return the {@link Builder}
	 */
	public static Builder with(OAuth2ClientRegistrationAuthenticationToken authentication) {
		return new Builder(authentication);
	}

	/**
	 * A builder for {@link OAuth2ClientRegistrationAuthenticationContext}.
	 */
	public static final class Builder
			extends AbstractBuilder<OAuth2ClientRegistrationAuthenticationContext, Builder> {

		private Builder(OAuth2ClientRegistrationAuthenticationToken authentication) {
			super(authentication);
		}

		/**
		 * Builds a new {@link OAuth2ClientRegistrationAuthenticationContext}.
		 * @return the {@link OAuth2ClientRegistrationAuthenticationContext}
		 */
		@Override
		public OAuth2ClientRegistrationAuthenticationContext build() {
			return new OAuth2ClientRegistrationAuthenticationContext(getContext());
		}

	}

}
