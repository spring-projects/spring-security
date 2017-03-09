/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.registration;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * @author Joe Grandja
 */
public class ClientRegistration {
	private String clientId;
	private String clientSecret;
	private ClientAuthenticationMethod clientAuthenticationMethod = ClientAuthenticationMethod.HEADER;
	private AuthorizationGrantType authorizedGrantType;
	private URI redirectUri;
	private Set<String> scopes = Collections.emptySet();
	private ProviderDetails providerDetails = new ProviderDetails();
	private String clientName;
	private String clientAlias;

	protected ClientRegistration() {
	}

	public final String getClientId() {
		return this.clientId;
	}

	public final String getClientSecret() {
		return this.clientSecret;
	}

	public final ClientAuthenticationMethod getClientAuthenticationMethod() {
		return this.clientAuthenticationMethod;
	}

	public final AuthorizationGrantType getAuthorizedGrantType() {
		return this.authorizedGrantType;
	}

	public final URI getRedirectUri() {
		return this.redirectUri;
	}

	public final Set<String> getScopes() {
		return this.scopes;
	}

	public final ProviderDetails getProviderDetails() {
		return this.providerDetails;
	}

	public final String getClientName() {
		return this.clientName;
	}

	public final String getClientAlias() {
		return this.clientAlias;
	}

	public class ProviderDetails {
		private URI authorizationUri;
		private URI tokenUri;
		private URI userInfoUri;
		private boolean openIdProvider;

		protected ProviderDetails() {
		}

		public final URI getAuthorizationUri() {
			return this.authorizationUri;
		}

		public final URI getTokenUri() {
			return this.tokenUri;
		}

		public final URI getUserInfoUri() {
			return this.userInfoUri;
		}

		public final boolean isOpenIdProvider() {
			return this.openIdProvider;
		}
	}

	public static class Builder {
		private final ClientRegistration clientRegistration;

		public Builder(String clientId) {
			this.clientRegistration = new ClientRegistration();
			this.clientRegistration.clientId = clientId;
		}

		public Builder(ClientRegistrationProperties clientRegistrationProperties) {
			this(clientRegistrationProperties.getClientId());
			this.clientSecret(clientRegistrationProperties.getClientSecret());
			this.clientAuthenticationMethod(clientRegistrationProperties.getClientAuthenticationMethod());
			this.authorizedGrantType(clientRegistrationProperties.getAuthorizedGrantType());
			this.redirectUri(clientRegistrationProperties.getRedirectUri());
			if (!CollectionUtils.isEmpty(clientRegistrationProperties.getScopes())) {
				this.scopes(clientRegistrationProperties.getScopes().stream().toArray(String[]::new));
			}
			this.authorizationUri(clientRegistrationProperties.getAuthorizationUri());
			this.tokenUri(clientRegistrationProperties.getTokenUri());
			this.userInfoUri(clientRegistrationProperties.getUserInfoUri());
			if (clientRegistrationProperties.isOpenIdProvider()) {
				this.openIdProvider();
			}
			this.clientName(clientRegistrationProperties.getClientName());
			this.clientAlias(clientRegistrationProperties.getClientAlias());
		}

		public final Builder clientSecret(String clientSecret) {
			this.clientRegistration.clientSecret = clientSecret;
			return this;
		}

		public final Builder clientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
			this.clientRegistration.clientAuthenticationMethod = clientAuthenticationMethod;
			return this;
		}

		public final Builder authorizedGrantType(AuthorizationGrantType authorizedGrantType) {
			this.clientRegistration.authorizedGrantType = authorizedGrantType;
			return this;
		}

		public final Builder redirectUri(String redirectUri) {
			this.clientRegistration.redirectUri = this.toURI(redirectUri);
			return this;
		}

		public final Builder scopes(String... scopes) {
			if (scopes != null && scopes.length > 0) {
				this.clientRegistration.scopes = Collections.unmodifiableSet(
						new LinkedHashSet<>(Arrays.asList(scopes)));
			}
			return this;
		}

		public final Builder authorizationUri(String authorizationUri) {
			this.clientRegistration.providerDetails.authorizationUri = this.toURI(authorizationUri);
			return this;
		}

		public final Builder tokenUri(String tokenUri) {
			this.clientRegistration.providerDetails.tokenUri = this.toURI(tokenUri);
			return this;
		}

		public final Builder userInfoUri(String userInfoUri) {
			this.clientRegistration.providerDetails.userInfoUri = this.toURI(userInfoUri);
			return this;
		}

		public final Builder openIdProvider() {
			this.clientRegistration.providerDetails.openIdProvider = true;
			return this;
		}

		public final Builder clientName(String clientName) {
			this.clientRegistration.clientName = clientName;
			return this;
		}

		public final Builder clientAlias(String clientAlias) {
			this.clientRegistration.clientAlias = clientAlias;
			return this;
		}

		public ClientRegistration build() {
			if (!AuthorizationGrantType.AUTHORIZATION_CODE.equals(this.clientRegistration.getAuthorizedGrantType())) {
				throw new UnsupportedOperationException((this.clientRegistration.getAuthorizedGrantType() != null ?
						this.clientRegistration.getAuthorizedGrantType().value() :
						"null") + " authorization grant type is currently not supported");
			}
			this.validateClientWithAuthorizationCodeGrantType();
			return this.clientRegistration;
		}

		private void validateClientWithAuthorizationCodeGrantType() {
			Assert.hasText(this.clientRegistration.clientId, "clientId cannot be empty");
			Assert.hasText(this.clientRegistration.clientSecret, "clientSecret cannot be empty");
			Assert.notNull(this.clientRegistration.clientAuthenticationMethod, "clientAuthenticationMethod cannot be null");
			Assert.notNull(this.clientRegistration.redirectUri, "redirectUri cannot be null");
			Assert.notEmpty(this.clientRegistration.scopes, "scopes cannot be empty");
			Assert.notNull(this.clientRegistration.providerDetails.authorizationUri, "authorizationUri cannot be null");
			Assert.notNull(this.clientRegistration.providerDetails.tokenUri, "tokenUri cannot be null");
			Assert.notNull(this.clientRegistration.providerDetails.userInfoUri, "userInfoUri cannot be null");
			Assert.hasText(this.clientRegistration.clientName, "clientName cannot be empty");
			Assert.hasText(this.clientRegistration.clientAlias, "clientAlias cannot be empty");
		}

		private URI toURI(String uriStr) {
			try {
				return new URI(uriStr);
			} catch (Exception ex) {
				throw new IllegalArgumentException("An error occurred parsing URI: " + uriStr, ex);
			}
		}
	}
}
