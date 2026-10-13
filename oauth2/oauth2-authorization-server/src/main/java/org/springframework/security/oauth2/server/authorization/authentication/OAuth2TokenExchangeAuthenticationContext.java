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

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthenticationContext} that holds an
 * {@link OAuth2TokenExchangeAuthenticationToken} and additional information and is used
 * when validating the OAuth 2.0 Token Exchange Grant Request.
 *
 * @author Rakesh Kumar Singh
 * @since 7.1
 * @see OAuth2AuthenticationContext
 * @see OAuth2TokenExchangeAuthenticationToken
 * @see OAuth2TokenExchangeAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
public final class OAuth2TokenExchangeAuthenticationContext implements OAuth2AuthenticationContext {

	private static final String ACTOR_AUTHORIZATION_ATTR_NAME = OAuth2TokenExchangeAuthenticationContext.class.getName()
		.concat(".actorAuthorization");

	private final Map<Object, Object> context;

	private OAuth2TokenExchangeAuthenticationContext(Map<Object, Object> context) {
		this.context = Collections.unmodifiableMap(new HashMap<>(context));
	}

	@SuppressWarnings("unchecked")
	@Override
	public <V> @Nullable V get(Object key) {
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
		RegisteredClient registeredClient = get(RegisteredClient.class);
		Assert.notNull(registeredClient, "registeredClient cannot be null");
		return registeredClient;
	}

	/**
	 * Returns the subject {@link OAuth2Authorization authorization}.
	 * @return the subject {@link OAuth2Authorization}
	 */
	public OAuth2Authorization getSubjectAuthorization() {
		OAuth2Authorization subjectAuthorization = get(OAuth2Authorization.class);
		Assert.notNull(subjectAuthorization, "subjectAuthorization cannot be null");
		return subjectAuthorization;
	}

	/**
	 * Returns the actor {@link OAuth2Authorization authorization}, or {@code null} if not
	 * available (impersonation case).
	 * @return the actor {@link OAuth2Authorization}, or {@code null}
	 */
	public @Nullable OAuth2Authorization getActorAuthorization() {
		return get(ACTOR_AUTHORIZATION_ATTR_NAME);
	}

	/**
	 * Constructs a new {@link Builder} with the provided
	 * {@link OAuth2TokenExchangeAuthenticationToken}.
	 * @param authentication the {@link OAuth2TokenExchangeAuthenticationToken}
	 * @return the {@link Builder}
	 */
	public static Builder with(OAuth2TokenExchangeAuthenticationToken authentication) {
		return new Builder(authentication);
	}

	/**
	 * A builder for {@link OAuth2TokenExchangeAuthenticationContext}.
	 */
	public static final class Builder
			extends AbstractBuilder<OAuth2TokenExchangeAuthenticationContext, Builder> {

		private Builder(OAuth2TokenExchangeAuthenticationToken authentication) {
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
		 * Sets the subject {@link OAuth2Authorization}.
		 * @param subjectAuthorization the subject {@link OAuth2Authorization}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder subjectAuthorization(OAuth2Authorization subjectAuthorization) {
			return put(OAuth2Authorization.class, subjectAuthorization);
		}

		/**
		 * Sets the actor {@link OAuth2Authorization}, or {@code null} for impersonation.
		 * @param actorAuthorization the actor {@link OAuth2Authorization}, may be
		 * {@code null}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder actorAuthorization(@Nullable OAuth2Authorization actorAuthorization) {
			if (actorAuthorization != null) {
				getContext().put(ACTOR_AUTHORIZATION_ATTR_NAME, actorAuthorization);
			}
			return getThis();
		}

		/**
		 * Builds a new {@link OAuth2TokenExchangeAuthenticationContext}.
		 * @return the {@link OAuth2TokenExchangeAuthenticationContext}
		 */
		@Override
		public OAuth2TokenExchangeAuthenticationContext build() {
			Assert.notNull(get(RegisteredClient.class), "registeredClient cannot be null");
			Assert.notNull(get(OAuth2Authorization.class), "subjectAuthorization cannot be null");
			return new OAuth2TokenExchangeAuthenticationContext(getContext());
		}

	}

}
