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
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthenticationContext} that holds an
 * {@link OAuth2DeviceVerificationAuthenticationToken} and additional information and is
 * used when determining if authorization consent is required.
 *
 * @author Dinesh Gupta
 * @since 7.0
 * @see OAuth2AuthenticationContext
 * @see OAuth2DeviceVerificationAuthenticationToken
 * @see OAuth2DeviceVerificationAuthenticationProvider#setAuthorizationConsentRequired(java.util.function.Predicate)
 */
public final class OAuth2DeviceVerificationAuthenticationContext implements OAuth2AuthenticationContext {

	private final Map<Object, Object> context;

	private OAuth2DeviceVerificationAuthenticationContext(Map<Object, Object> context) {
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
	 * Returns the {@link OAuth2Authorization authorization}.
	 * @return the {@link OAuth2Authorization}
	 */
	public OAuth2Authorization getAuthorization() {
		return get(OAuth2Authorization.class);
	}

	/**
	 * Returns the {@link OAuth2AuthorizationConsent authorization consent}.
	 * @return the {@link OAuth2AuthorizationConsent}, or {@code null} if not available
	 */
	@Nullable
	public OAuth2AuthorizationConsent getAuthorizationConsent() {
		return get(OAuth2AuthorizationConsent.class);
	}

	/**
	 * Returns the requested scopes.
	 * @return the requested scopes
	 */
	public Set<String> getRequestedScopes() {
		Set<String> requestedScopes = getAuthorization().getAttribute(OAuth2ParameterNames.SCOPE);
		return (requestedScopes != null) ? requestedScopes : Collections.emptySet();
	}

	/**
	 * Constructs a new {@link Builder} with the provided
	 * {@link OAuth2DeviceVerificationAuthenticationToken}.
	 * @param authentication the {@link OAuth2DeviceVerificationAuthenticationToken}
	 * @return the {@link Builder}
	 */
	public static Builder with(OAuth2DeviceVerificationAuthenticationToken authentication) {
		return new Builder(authentication);
	}

	/**
	 * A builder for {@link OAuth2DeviceVerificationAuthenticationContext}.
	 */
	public static final class Builder extends AbstractBuilder<OAuth2DeviceVerificationAuthenticationContext, Builder> {

		private Builder(OAuth2DeviceVerificationAuthenticationToken authentication) {
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
		 * Sets the {@link OAuth2Authorization authorization}.
		 * @param authorization the {@link OAuth2Authorization}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder authorization(OAuth2Authorization authorization) {
			return put(OAuth2Authorization.class, authorization);
		}

		/**
		 * Sets the {@link OAuth2AuthorizationConsent authorization consent}.
		 * @param authorizationConsent the {@link OAuth2AuthorizationConsent}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder authorizationConsent(OAuth2AuthorizationConsent authorizationConsent) {
			return put(OAuth2AuthorizationConsent.class, authorizationConsent);
		}

		/**
		 * Builds a new {@link OAuth2DeviceVerificationAuthenticationContext}.
		 * @return the {@link OAuth2DeviceVerificationAuthenticationContext}
		 */
		@Override
		public OAuth2DeviceVerificationAuthenticationContext build() {
			Assert.notNull(get(RegisteredClient.class), "registeredClient cannot be null");
			Assert.notNull(get(OAuth2Authorization.class), "authorization cannot be null");
			return new OAuth2DeviceVerificationAuthenticationContext(getContext());
		}

	}

}
