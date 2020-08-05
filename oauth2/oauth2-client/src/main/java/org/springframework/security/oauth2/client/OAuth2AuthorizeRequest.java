/*
 * Copyright 2002-2020 the original author or authors.
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
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Represents a request the {@link OAuth2AuthorizedClientManager} uses to
 * {@link OAuth2AuthorizedClientManager#authorize(OAuth2AuthorizeRequest) authorize} (or
 * re-authorize) the {@link ClientRegistration client} identified by the provided
 * {@link #getClientRegistrationId() clientRegistrationId}.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see OAuth2AuthorizedClientManager
 */
public final class OAuth2AuthorizeRequest {

	private String clientRegistrationId;

	private OAuth2AuthorizedClient authorizedClient;

	private Authentication principal;

	private Map<String, Object> attributes;

	private OAuth2AuthorizeRequest() {
	}

	/**
	 * Returns the identifier for the {@link ClientRegistration client registration}.
	 * @return the identifier for the client registration
	 */
	public String getClientRegistrationId() {
		return this.clientRegistrationId;
	}

	/**
	 * Returns the {@link OAuth2AuthorizedClient authorized client} or {@code null} if it
	 * was not provided.
	 * @return the {@link OAuth2AuthorizedClient} or {@code null} if it was not provided
	 */
	@Nullable
	public OAuth2AuthorizedClient getAuthorizedClient() {
		return this.authorizedClient;
	}

	/**
	 * Returns the {@code Principal} (to be) associated to the authorized client.
	 * @return the {@code Principal} (to be) associated to the authorized client
	 */
	public Authentication getPrincipal() {
		return this.principal;
	}

	/**
	 * Returns the attributes associated to the request.
	 * @return a {@code Map} of the attributes associated to the request
	 */
	public Map<String, Object> getAttributes() {
		return this.attributes;
	}

	/**
	 * Returns the value of an attribute associated to the request or {@code null} if not
	 * available.
	 * @param name the name of the attribute
	 * @param <T> the type of the attribute
	 * @return the value of the attribute associated to the request
	 */
	@Nullable
	@SuppressWarnings("unchecked")
	public <T> T getAttribute(String name) {
		return (T) this.getAttributes().get(name);
	}

	/**
	 * Returns a new {@link Builder} initialized with the identifier for the
	 * {@link ClientRegistration client registration}.
	 * @param clientRegistrationId the identifier for the {@link ClientRegistration client
	 * registration}
	 * @return the {@link Builder}
	 */
	public static Builder withClientRegistrationId(String clientRegistrationId) {
		return new Builder(clientRegistrationId);
	}

	/**
	 * Returns a new {@link Builder} initialized with the {@link OAuth2AuthorizedClient
	 * authorized client}.
	 * @param authorizedClient the {@link OAuth2AuthorizedClient authorized client}
	 * @return the {@link Builder}
	 */
	public static Builder withAuthorizedClient(OAuth2AuthorizedClient authorizedClient) {
		return new Builder(authorizedClient);
	}

	/**
	 * A builder for {@link OAuth2AuthorizeRequest}.
	 */
	public static class Builder {

		private String clientRegistrationId;

		private OAuth2AuthorizedClient authorizedClient;

		private Authentication principal;

		private Map<String, Object> attributes;

		private Builder(String clientRegistrationId) {
			Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
			this.clientRegistrationId = clientRegistrationId;
		}

		private Builder(OAuth2AuthorizedClient authorizedClient) {
			Assert.notNull(authorizedClient, "authorizedClient cannot be null");
			this.authorizedClient = authorizedClient;
		}

		/**
		 * Sets the name of the {@code Principal} (to be) associated to the authorized
		 * client.
		 *
		 * @since 5.3
		 * @param principalName the name of the {@code Principal} (to be) associated to
		 * the authorized client
		 * @return the {@link Builder}
		 */
		public Builder principal(String principalName) {
			return principal(createAuthentication(principalName));
		}

		private static Authentication createAuthentication(final String principalName) {
			Assert.hasText(principalName, "principalName cannot be empty");

			return new AbstractAuthenticationToken(null) {
				@Override
				public Object getCredentials() {
					return "";
				}

				@Override
				public Object getPrincipal() {
					return principalName;
				}
			};
		}

		/**
		 * Sets the {@code Principal} (to be) associated to the authorized client.
		 * @param principal the {@code Principal} (to be) associated to the authorized
		 * client
		 * @return the {@link Builder}
		 */
		public Builder principal(Authentication principal) {
			this.principal = principal;
			return this;
		}

		/**
		 * Provides a {@link Consumer} access to the attributes associated to the request.
		 * @param attributesConsumer a {@link Consumer} of the attributes associated to
		 * the request
		 * @return the {@link Builder}
		 */
		public Builder attributes(Consumer<Map<String, Object>> attributesConsumer) {
			if (this.attributes == null) {
				this.attributes = new HashMap<>();
			}
			attributesConsumer.accept(this.attributes);
			return this;
		}

		/**
		 * Sets an attribute associated to the request.
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
		 * Builds a new {@link OAuth2AuthorizeRequest}.
		 * @return a {@link OAuth2AuthorizeRequest}
		 */
		public OAuth2AuthorizeRequest build() {
			Assert.notNull(this.principal, "principal cannot be null");
			OAuth2AuthorizeRequest authorizeRequest = new OAuth2AuthorizeRequest();
			if (this.authorizedClient != null) {
				authorizeRequest.clientRegistrationId = this.authorizedClient.getClientRegistration()
						.getRegistrationId();
				authorizeRequest.authorizedClient = this.authorizedClient;
			}
			else {
				authorizeRequest.clientRegistrationId = this.clientRegistrationId;
			}
			authorizeRequest.principal = this.principal;
			authorizeRequest.attributes = Collections.unmodifiableMap(CollectionUtils.isEmpty(this.attributes)
					? Collections.emptyMap() : new LinkedHashMap<>(this.attributes));
			return authorizeRequest;
		}

	}

}
