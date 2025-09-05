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
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthenticationContext} that holds an
 * {@link OAuth2ClientAuthenticationToken} and additional information and is used when
 * validating an OAuth 2.0 Client Authentication.
 *
 * @author Joe Grandja
 * @since 1.3
 * @see OAuth2AuthenticationContext
 * @see OAuth2ClientAuthenticationToken
 * @see X509ClientCertificateAuthenticationProvider#setCertificateVerifier(Consumer)
 */
public final class OAuth2ClientAuthenticationContext implements OAuth2AuthenticationContext {

	private final Map<Object, Object> context;

	private OAuth2ClientAuthenticationContext(Map<Object, Object> context) {
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
	 * Returns the {@link RegisteredClient registered client}.
	 * @return the {@link RegisteredClient}
	 */
	public RegisteredClient getRegisteredClient() {
		return get(RegisteredClient.class);
	}

	/**
	 * Constructs a new {@link Builder} with the provided
	 * {@link OAuth2ClientAuthenticationToken}.
	 * @param authentication the {@link OAuth2ClientAuthenticationToken}
	 * @return the {@link Builder}
	 */
	public static Builder with(OAuth2ClientAuthenticationToken authentication) {
		return new Builder(authentication);
	}

	/**
	 * A builder for {@link OAuth2ClientAuthenticationContext}.
	 */
	public static final class Builder extends AbstractBuilder<OAuth2ClientAuthenticationContext, Builder> {

		private Builder(OAuth2ClientAuthenticationToken authentication) {
			super(authentication);
		}

		/**
		 * Sets the {@link RegisteredClient registered client}.
		 * @param registeredClient the {@link RegisteredClient}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder registeredClient(RegisteredClient registeredClient) {
			return put(RegisteredClient.class, registeredClient);
		}

		/**
		 * Builds a new {@link OAuth2ClientAuthenticationContext}.
		 * @return the {@link OAuth2ClientAuthenticationContext}
		 */
		@Override
		public OAuth2ClientAuthenticationContext build() {
			Assert.notNull(get(RegisteredClient.class), "registeredClient cannot be null");
			return new OAuth2ClientAuthenticationContext(getContext());
		}

	}

}
