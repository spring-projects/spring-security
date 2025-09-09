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
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthenticationContext} that holds an
 * {@link OAuth2AuthorizationConsent.Builder} and additional information and is used when
 * customizing the building of the {@link OAuth2AuthorizationConsent}.
 *
 * @author Steve Riesenberg
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2AuthenticationContext
 * @see OAuth2AuthorizationConsent
 * @see OAuth2AuthorizationConsentAuthenticationProvider#setAuthorizationConsentCustomizer(Consumer)
 */
public final class OAuth2AuthorizationConsentAuthenticationContext implements OAuth2AuthenticationContext {

	private final Map<Object, Object> context;

	private OAuth2AuthorizationConsentAuthenticationContext(Map<Object, Object> context) {
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
	 * Returns the {@link OAuth2AuthorizationConsent.Builder authorization consent
	 * builder}.
	 * @return the {@link OAuth2AuthorizationConsent.Builder}
	 */
	public OAuth2AuthorizationConsent.Builder getAuthorizationConsent() {
		return get(OAuth2AuthorizationConsent.Builder.class);
	}

	/**
	 * Returns the {@link RegisteredClient registered client}.
	 * @return the {@link RegisteredClient}
	 */
	public RegisteredClient getRegisteredClient() {
		return get(RegisteredClient.class);
	}

	/**
	 * Returns the {@link OAuth2Authorization authorization}.
	 * @return the {@link OAuth2Authorization}
	 */
	public OAuth2Authorization getAuthorization() {
		return get(OAuth2Authorization.class);
	}

	/**
	 * Returns the {@link OAuth2AuthorizationRequest authorization request}.
	 * @return the {@link OAuth2AuthorizationRequest}
	 */
	public OAuth2AuthorizationRequest getAuthorizationRequest() {
		return get(OAuth2AuthorizationRequest.class);
	}

	/**
	 * Constructs a new {@link Builder} with the provided
	 * {@link OAuth2AuthorizationConsentAuthenticationToken}.
	 * @param authentication the {@link OAuth2AuthorizationConsentAuthenticationToken}
	 * @return the {@link Builder}
	 */
	public static Builder with(OAuth2AuthorizationConsentAuthenticationToken authentication) {
		return new Builder(authentication);
	}

	/**
	 * A builder for {@link OAuth2AuthorizationConsentAuthenticationContext}.
	 */
	public static final class Builder
			extends AbstractBuilder<OAuth2AuthorizationConsentAuthenticationContext, Builder> {

		private Builder(OAuth2AuthorizationConsentAuthenticationToken authentication) {
			super(authentication);
		}

		/**
		 * Sets the {@link OAuth2AuthorizationConsent.Builder authorization consent
		 * builder}.
		 * @param authorizationConsent the {@link OAuth2AuthorizationConsent.Builder}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder authorizationConsent(OAuth2AuthorizationConsent.Builder authorizationConsent) {
			return put(OAuth2AuthorizationConsent.Builder.class, authorizationConsent);
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
		 * Sets the {@link OAuth2Authorization authorization}.
		 * @param authorization the {@link OAuth2Authorization}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder authorization(OAuth2Authorization authorization) {
			return put(OAuth2Authorization.class, authorization);
		}

		/**
		 * Sets the {@link OAuth2AuthorizationRequest authorization request}.
		 * @param authorizationRequest the {@link OAuth2AuthorizationRequest}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder authorizationRequest(OAuth2AuthorizationRequest authorizationRequest) {
			return put(OAuth2AuthorizationRequest.class, authorizationRequest);
		}

		/**
		 * Builds a new {@link OAuth2AuthorizationConsentAuthenticationContext}.
		 * @return the {@link OAuth2AuthorizationConsentAuthenticationContext}
		 */
		@Override
		public OAuth2AuthorizationConsentAuthenticationContext build() {
			Assert.notNull(get(OAuth2AuthorizationConsent.Builder.class), "authorizationConsentBuilder cannot be null");
			Assert.notNull(get(RegisteredClient.class), "registeredClient cannot be null");
			OAuth2Authorization authorization = get(OAuth2Authorization.class);
			Assert.notNull(authorization, "authorization cannot be null");
			if (authorization.getAuthorizationGrantType().equals(AuthorizationGrantType.AUTHORIZATION_CODE)) {
				Assert.notNull(get(OAuth2AuthorizationRequest.class), "authorizationRequest cannot be null");
			}
			return new OAuth2AuthorizationConsentAuthenticationContext(getContext());
		}

	}

}
