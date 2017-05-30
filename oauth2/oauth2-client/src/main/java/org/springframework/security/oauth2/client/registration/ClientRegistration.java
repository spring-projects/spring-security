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

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A representation of a client registration with an <i>OAuth 2.0 Authorization Server</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-2">Section 2 Client Registration</a>
 */
public class ClientRegistration {
	private String clientId;
	private String clientSecret;
	private ClientAuthenticationMethod clientAuthenticationMethod = ClientAuthenticationMethod.BASIC;
	private AuthorizationGrantType authorizedGrantType;
	private String redirectUri;
	private Set<String> scopes = Collections.emptySet();
	private ProviderDetails providerDetails = new ProviderDetails();
	private String clientName;
	private String clientAlias;

	protected ClientRegistration() {
	}

	public String getClientId() {
		return this.clientId;
	}

	protected void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return this.clientSecret;
	}

	protected void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public ClientAuthenticationMethod getClientAuthenticationMethod() {
		return this.clientAuthenticationMethod;
	}

	protected void setClientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
		this.clientAuthenticationMethod = clientAuthenticationMethod;
	}

	public AuthorizationGrantType getAuthorizedGrantType() {
		return this.authorizedGrantType;
	}

	protected void setAuthorizedGrantType(AuthorizationGrantType authorizedGrantType) {
		this.authorizedGrantType = authorizedGrantType;
	}

	public String getRedirectUri() {
		return this.redirectUri;
	}

	protected void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}

	public Set<String> getScopes() {
		return this.scopes;
	}

	protected void setScopes(Set<String> scopes) {
		this.scopes = scopes;
	}

	public ProviderDetails getProviderDetails() {
		return this.providerDetails;
	}

	protected void setProviderDetails(ProviderDetails providerDetails) {
		this.providerDetails = providerDetails;
	}

	public String getClientName() {
		return this.clientName;
	}

	protected void setClientName(String clientName) {
		this.clientName = clientName;
	}

	public String getClientAlias() {
		return this.clientAlias;
	}

	protected void setClientAlias(String clientAlias) {
		this.clientAlias = clientAlias;
	}

	public class ProviderDetails {
		private String authorizationUri;
		private String tokenUri;
		private String userInfoUri;

		protected ProviderDetails() {
		}

		public String getAuthorizationUri() {
			return this.authorizationUri;
		}

		protected void setAuthorizationUri(String authorizationUri) {
			this.authorizationUri = authorizationUri;
		}

		public String getTokenUri() {
			return this.tokenUri;
		}

		protected void setTokenUri(String tokenUri) {
			this.tokenUri = tokenUri;
		}

		public String getUserInfoUri() {
			return this.userInfoUri;
		}

		protected void setUserInfoUri(String userInfoUri) {
			this.userInfoUri = userInfoUri;
		}
	}

	public static class Builder {
		protected String clientId;
		protected String clientSecret;
		protected ClientAuthenticationMethod clientAuthenticationMethod = ClientAuthenticationMethod.BASIC;
		protected AuthorizationGrantType authorizedGrantType;
		protected String redirectUri;
		protected Set<String> scopes;
		protected String authorizationUri;
		protected String tokenUri;
		protected String userInfoUri;
		protected String clientName;
		protected String clientAlias;

		public Builder(String clientId) {
			this.clientId = clientId;
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
			this.clientName(clientRegistrationProperties.getClientName());
			this.clientAlias(clientRegistrationProperties.getClientAlias());
		}

		public Builder clientSecret(String clientSecret) {
			this.clientSecret = clientSecret;
			return this;
		}

		public Builder clientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
			this.clientAuthenticationMethod = clientAuthenticationMethod;
			return this;
		}

		public Builder authorizedGrantType(AuthorizationGrantType authorizedGrantType) {
			this.authorizedGrantType = authorizedGrantType;
			return this;
		}

		public Builder redirectUri(String redirectUri) {
			this.redirectUri = redirectUri;
			return this;
		}

		public Builder scopes(String... scopes) {
			if (scopes != null && scopes.length > 0) {
				this.scopes = Collections.unmodifiableSet(
						new LinkedHashSet<>(Arrays.asList(scopes)));
			}
			return this;
		}

		public Builder authorizationUri(String authorizationUri) {
			this.authorizationUri = authorizationUri;
			return this;
		}

		public Builder tokenUri(String tokenUri) {
			this.tokenUri = tokenUri;
			return this;
		}

		public Builder userInfoUri(String userInfoUri) {
			this.userInfoUri = userInfoUri;
			return this;
		}

		public Builder clientName(String clientName) {
			this.clientName = clientName;
			return this;
		}

		public Builder clientAlias(String clientAlias) {
			this.clientAlias = clientAlias;
			return this;
		}

		public ClientRegistration build() {
			this.validateClientWithAuthorizationCodeGrantType();
			ClientRegistration clientRegistration = new ClientRegistration();
			this.setProperties(clientRegistration);
			return clientRegistration;
		}

		protected void setProperties(ClientRegistration clientRegistration) {
			clientRegistration.setClientId(this.clientId);
			clientRegistration.setClientSecret(this.clientSecret);
			clientRegistration.setClientAuthenticationMethod(this.clientAuthenticationMethod);
			clientRegistration.setAuthorizedGrantType(this.authorizedGrantType);
			clientRegistration.setRedirectUri(this.redirectUri);
			clientRegistration.setScopes(this.scopes);

			ProviderDetails providerDetails = clientRegistration.new ProviderDetails();
			providerDetails.setAuthorizationUri(this.authorizationUri);
			providerDetails.setTokenUri(this.tokenUri);
			providerDetails.setUserInfoUri(this.userInfoUri);
			clientRegistration.setProviderDetails(providerDetails);

			clientRegistration.setClientName(this.clientName);
			clientRegistration.setClientAlias(this.clientAlias);
		}

		protected void validateClientWithAuthorizationCodeGrantType() {
			Assert.isTrue(AuthorizationGrantType.AUTHORIZATION_CODE.equals(this.authorizedGrantType),
				"authorizedGrantType must be " + AuthorizationGrantType.AUTHORIZATION_CODE.value());
			Assert.hasText(this.clientId, "clientId cannot be empty");
			Assert.hasText(this.clientSecret, "clientSecret cannot be empty");
			Assert.notNull(this.clientAuthenticationMethod, "clientAuthenticationMethod cannot be null");
			Assert.hasText(this.redirectUri, "redirectUri cannot be empty");
			Assert.notEmpty(this.scopes, "scopes cannot be empty");
			Assert.hasText(this.authorizationUri, "authorizationUri cannot be empty");
			Assert.hasText(this.tokenUri, "tokenUri cannot be empty");
			Assert.hasText(this.userInfoUri, "userInfoUri cannot be empty");
			Assert.hasText(this.clientName, "clientName cannot be empty");
			Assert.hasText(this.clientAlias, "clientAlias cannot be empty");
		}
	}
}
