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
import java.util.function.Predicate;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthenticationContext} that holds an
 * {@link OAuth2AuthorizationCodeRequestAuthenticationToken} and additional information
 * and is used when validating the OAuth 2.0 Authorization Request parameters, as well as,
 * determining if authorization consent is required.
 *
 * @author Joe Grandja
 * @since 0.4.0
 * @see OAuth2AuthenticationContext
 * @see OAuth2AuthorizationCodeRequestAuthenticationToken
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider#setAuthenticationValidator(Consumer)
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider#setAuthorizationConsentRequired(Predicate)
 */
public final class OAuth2AuthorizationCodeRequestAuthenticationContext implements OAuth2AuthenticationContext {

	private final Map<Object, Object> context;

	private OAuth2AuthorizationCodeRequestAuthenticationContext(Map<Object, Object> context) {
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
	 * Returns the {@link OAuth2AuthorizationRequest authorization request}.
	 * @return the {@link OAuth2AuthorizationRequest}
	 * @since 1.3
	 */
	@Nullable
	public OAuth2AuthorizationRequest getAuthorizationRequest() {
		return get(OAuth2AuthorizationRequest.class);
	}

	/**
	 * Returns the {@link OAuth2AuthorizationConsent authorization consent}.
	 * @return the {@link OAuth2AuthorizationConsent}
	 * @since 1.3
	 */
	@Nullable
	public OAuth2AuthorizationConsent getAuthorizationConsent() {
		return get(OAuth2AuthorizationConsent.class);
	}

	/**
	 * Constructs a new {@link Builder} with the provided
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationToken}.
	 * @param authentication the {@link OAuth2AuthorizationCodeRequestAuthenticationToken}
	 * @return the {@link Builder}
	 */
	public static Builder with(OAuth2AuthorizationCodeRequestAuthenticationToken authentication) {
		return new Builder(authentication);
	}

	/**
	 * A builder for {@link OAuth2AuthorizationCodeRequestAuthenticationContext}.
	 */
	public static final class Builder
			extends AbstractBuilder<OAuth2AuthorizationCodeRequestAuthenticationContext, Builder> {

		private Builder(OAuth2AuthorizationCodeRequestAuthenticationToken authentication) {
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
		 * Sets the {@link OAuth2AuthorizationRequest authorization request}.
		 * @param authorizationRequest the {@link OAuth2AuthorizationRequest}
		 * @return the {@link Builder} for further configuration
		 * @since 1.3
		 */
		public Builder authorizationRequest(OAuth2AuthorizationRequest authorizationRequest) {
			return put(OAuth2AuthorizationRequest.class, authorizationRequest);
		}

		/**
		 * Sets the {@link OAuth2AuthorizationConsent authorization consent}.
		 * @param authorizationConsent the {@link OAuth2AuthorizationConsent}
		 * @return the {@link Builder} for further configuration
		 * @since 1.3
		 */
		public Builder authorizationConsent(OAuth2AuthorizationConsent authorizationConsent) {
			return put(OAuth2AuthorizationConsent.class, authorizationConsent);
		}

		/**
		 * Builds a new {@link OAuth2AuthorizationCodeRequestAuthenticationContext}.
		 * @return the {@link OAuth2AuthorizationCodeRequestAuthenticationContext}
		 */
		@Override
		public OAuth2AuthorizationCodeRequestAuthenticationContext build() {
			Assert.notNull(get(RegisteredClient.class), "registeredClient cannot be null");
			return new OAuth2AuthorizationCodeRequestAuthenticationContext(getContext());
		}

	}

}
