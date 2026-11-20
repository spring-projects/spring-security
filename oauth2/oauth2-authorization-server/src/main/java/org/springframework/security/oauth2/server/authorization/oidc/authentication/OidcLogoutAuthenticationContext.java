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

package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationContext;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2AuthenticationContext} that holds an
 * {@link OidcLogoutAuthenticationToken} and additional information and is used when
 * validating the OpenID Connect RP-Initiated Logout Request parameters.
 *
 * @author Daniel Garnier-Moiroux
 * @since 7.0
 * @see OAuth2AuthenticationContext
 * @see OidcLogoutAuthenticationToken
 * @see OidcLogoutAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
public final class OidcLogoutAuthenticationContext implements OAuth2AuthenticationContext {

	private final Map<Object, Object> context;

	private OidcLogoutAuthenticationContext(Map<Object, Object> context) {
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
	 * Returns the {@link OidcIdToken ID Token} associated with the {@code id_token_hint},
	 * or {@code null} if not available.
	 * @return the {@link OidcIdToken}, or {@code null} if not available
	 * @since 7.3
	 * @see OidcLogoutAuthenticationProvider#setSessionValidator(Consumer)
	 */
	public @Nullable OidcIdToken getIdToken() {
		return get(OidcIdToken.class);
	}

	/**
	 * Returns the {@link SessionInformation} of the End-User's current session, or
	 * {@code null} if not available.
	 * @return the {@link SessionInformation}, or {@code null} if not available
	 * @since 7.3
	 * @see OidcLogoutAuthenticationProvider#setSessionValidator(Consumer)
	 */
	public @Nullable SessionInformation getSessionInformation() {
		return get(SessionInformation.class);
	}

	/**
	 * Constructs a new {@link Builder} with the provided
	 * {@link OidcLogoutAuthenticationToken}.
	 * @param authentication the {@link OidcLogoutAuthenticationToken}
	 * @return the {@link Builder}
	 */
	public static Builder with(OidcLogoutAuthenticationToken authentication) {
		return new Builder(authentication);
	}

	/**
	 * A builder for {@link OidcLogoutAuthenticationContext}.
	 */
	public static final class Builder extends AbstractBuilder<OidcLogoutAuthenticationContext, Builder> {

		private Builder(OidcLogoutAuthenticationToken authentication) {
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
		 * Sets the {@link OidcIdToken ID Token} associated with the
		 * {@code id_token_hint}.
		 * @param idToken the {@link OidcIdToken}
		 * @return the {@link Builder} for further configuration
		 * @since 7.3
		 */
		public Builder idToken(OidcIdToken idToken) {
			return put(OidcIdToken.class, idToken);
		}

		/**
		 * Sets the {@link SessionInformation} of the End-User's current session.
		 * @param sessionInformation the {@link SessionInformation}
		 * @return the {@link Builder} for further configuration
		 * @since 7.3
		 */
		public Builder sessionInformation(SessionInformation sessionInformation) {
			return put(SessionInformation.class, sessionInformation);
		}

		/**
		 * Builds a new {@link OidcLogoutAuthenticationContext}.
		 * @return the {@link OidcLogoutAuthenticationContext}
		 */
		@Override
		public OidcLogoutAuthenticationContext build() {
			Assert.notNull(get(RegisteredClient.class), "registeredClient cannot be null");
			return new OidcLogoutAuthenticationContext(getContext());
		}

	}

}
