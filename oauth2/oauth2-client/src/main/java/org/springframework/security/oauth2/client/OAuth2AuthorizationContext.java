/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.oauth2.client;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A context that holds authorization-specific state and is used by an {@link OAuth2AuthorizedClientProvider}
 * when attempting to authorize (or re-authorize) an OAuth 2.0 Client.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see OAuth2AuthorizedClientProvider
 */
public final class OAuth2AuthorizationContext {
	private ClientRegistration clientRegistration;
	private OAuth2AuthorizedClient authorizedClient;
	private Authentication principal;
	private Map<String, Object> attributes;

	private OAuth2AuthorizationContext() {
	}

	/**
	 * Returns the {@link ClientRegistration client registration}.
	 *
	 * @return the {@link ClientRegistration}
	 */
	public ClientRegistration getClientRegistration() {
		return this.clientRegistration;
	}

	/**
	 * Returns the {@link OAuth2AuthorizedClient authorized client} or {@code null}
	 * if the {@link #forClient(ClientRegistration) client registration} was supplied.
	 *
	 * @return the {@link OAuth2AuthorizedClient} or {@code null} if the client registration was supplied
	 */
	@Nullable
	public OAuth2AuthorizedClient getAuthorizedClient() {
		return this.authorizedClient;
	}

	/**
	 * Returns the {@code Principal} (to be) associated to the authorized client.
	 *
	 * @return the {@code Principal} (to be) associated to the authorized client
	 */
	public Authentication getPrincipal() {
		return this.principal;
	}

	/**
	 * Returns the attributes associated to the context.
	 *
	 * @return a {@code Map} of the attributes associated to the context
	 */
	public Map<String, Object> getAttributes() {
		return this.attributes;
	}

	/**
	 * Returns the value of an attribute associated to the context or {@code null} if not available.
	 *
	 * @param name the name of the attribute
	 * @param <T> the type of the attribute
	 * @return the value of the attribute associated to the context
	 */
	@Nullable
	@SuppressWarnings("unchecked")
	public <T> T getAttribute(String name) {
		return (T) this.getAttributes().get(name);
	}

	/**
	 * Returns a new {@link Builder} initialized with the {@link ClientRegistration}.
	 *
	 * @param clientRegistration the {@link ClientRegistration client registration}
	 * @return the {@link Builder}
	 */
	public static Builder forClient(ClientRegistration clientRegistration) {
		return new Builder(clientRegistration);
	}

	/**
	 * Returns a new {@link Builder} initialized with the {@link OAuth2AuthorizedClient}.
	 *
	 * @param authorizedClient the {@link OAuth2AuthorizedClient authorized client}
	 * @return the {@link Builder}
	 */
	public static Builder forClient(OAuth2AuthorizedClient authorizedClient) {
		return new Builder(authorizedClient);
	}

	/**
	 * A builder for {@link OAuth2AuthorizationContext}.
	 */
	public static class Builder {
		private ClientRegistration clientRegistration;
		private OAuth2AuthorizedClient authorizedClient;
		private Authentication principal;
		private Map<String, Object> attributes;

		private Builder(ClientRegistration clientRegistration) {
			Assert.notNull(clientRegistration, "clientRegistration cannot be null");
			this.clientRegistration = clientRegistration;
		}

		private Builder(OAuth2AuthorizedClient authorizedClient) {
			Assert.notNull(authorizedClient, "authorizedClient cannot be null");
			this.authorizedClient = authorizedClient;
		}

		/**
		 * Sets the {@code Principal} (to be) associated to the authorized client.
		 *
		 * @param principal the {@code Principal} (to be) associated to the authorized client
		 * @return the {@link Builder}
		 */
		public Builder principal(Authentication principal) {
			this.principal = principal;
			return this;
		}

		/**
		 * Sets the attributes associated to the context.
		 *
		 * @param attributes the attributes associated to the context
		 * @return the {@link Builder}
		 */
		public Builder attributes(Map<String, Object> attributes) {
			this.attributes = attributes;
			return this;
		}

		/**
		 * Sets an attribute associated to the context.
		 *
		 * @param name the name of the attribute
		 * @param value the value of the attribute
		 * @return the {@link Builder}
		 */
		public Builder attribute(String name, Object value) {
			if (this.attributes == null) {
				this.attributes = new HashMap<>();
			}
			this.attributes.put(name, value);
			return this;
		}

		/**
		 * Builds a new {@link OAuth2AuthorizationContext}.
		 *
		 * @return a {@link OAuth2AuthorizationContext}
		 */
		public OAuth2AuthorizationContext build() {
			Assert.notNull(this.principal, "principal cannot be null");
			OAuth2AuthorizationContext context = new OAuth2AuthorizationContext();
			if (this.authorizedClient != null) {
				context.clientRegistration = this.authorizedClient.getClientRegistration();
				context.authorizedClient = this.authorizedClient;
			} else {
				context.clientRegistration = this.clientRegistration;
			}
			context.principal = this.principal;
			context.attributes = Collections.unmodifiableMap(
					CollectionUtils.isEmpty(this.attributes) ?
							Collections.emptyMap() : new LinkedHashMap<>(this.attributes));
			return context;
		}
	}
}
