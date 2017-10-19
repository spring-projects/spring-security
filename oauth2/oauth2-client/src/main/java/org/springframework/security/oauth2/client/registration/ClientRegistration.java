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
import org.springframework.security.oauth2.oidc.core.OidcScope;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A representation of a client registration with an OAuth 2.0 / OpenID Connect 1.0 <i>Authorization Server</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-2">Section 2 Client Registration</a>
 */
public class ClientRegistration {
	private String registrationId;
	private String clientId;
	private String clientSecret;
	private ClientAuthenticationMethod clientAuthenticationMethod = ClientAuthenticationMethod.BASIC;
	private AuthorizationGrantType authorizationGrantType;
	private String redirectUri;
	private Set<String> scopes = Collections.emptySet();
	private ProviderDetails providerDetails = new ProviderDetails();
	private String clientName;

	protected ClientRegistration() {
	}

	public String getRegistrationId() {
		return this.registrationId;
	}

	protected void setRegistrationId(String registrationId) {
		this.registrationId = registrationId;
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

	public AuthorizationGrantType getAuthorizationGrantType() {
		return this.authorizationGrantType;
	}

	protected void setAuthorizationGrantType(AuthorizationGrantType authorizationGrantType) {
		this.authorizationGrantType = authorizationGrantType;
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

	public class ProviderDetails {
		private String authorizationUri;
		private String tokenUri;
		private UserInfoEndpoint userInfoEndpoint = new UserInfoEndpoint();
		private String jwkSetUri;

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

		public UserInfoEndpoint getUserInfoEndpoint() {
			return this.userInfoEndpoint;
		}

		protected void setUserInfoEndpoint(UserInfoEndpoint userInfoEndpoint) {
			this.userInfoEndpoint = userInfoEndpoint;
		}

		public String getJwkSetUri() {
			return this.jwkSetUri;
		}

		protected void setJwkSetUri(String jwkSetUri) {
			this.jwkSetUri = jwkSetUri;
		}

		public class UserInfoEndpoint {
			private String uri;
			private String userNameAttributeName;

			protected UserInfoEndpoint() {
			}

			public String getUri() {
				return this.uri;
			}

			protected void setUri(String uri) {
				this.uri = uri;
			}

			public String getUserNameAttributeName() {
				return this.userNameAttributeName;
			}

			protected void setUserNameAttributeName(String userNameAttributeName) {
				this.userNameAttributeName = userNameAttributeName;
			}
		}
	}

	public static class Builder {
		private String registrationId;
		private String clientId;
		private String clientSecret;
		private ClientAuthenticationMethod clientAuthenticationMethod = ClientAuthenticationMethod.BASIC;
		private AuthorizationGrantType authorizationGrantType;
		private String redirectUri;
		private Set<String> scopes;
		private String authorizationUri;
		private String tokenUri;
		private String userInfoUri;
		private String userNameAttributeName;
		private String jwkSetUri;
		private String clientName;

		public Builder(String registrationId) {
			this.registrationId = registrationId;
		}

		public Builder(ClientRegistration clientRegistration) {
			this(clientRegistration.getRegistrationId());
			this.clientId(clientRegistration.getClientId());
			this.clientSecret(clientRegistration.getClientSecret());
			this.clientAuthenticationMethod(clientRegistration.getClientAuthenticationMethod());
			this.authorizationGrantType(clientRegistration.getAuthorizationGrantType());
			this.redirectUri(clientRegistration.getRedirectUri());
			if (!CollectionUtils.isEmpty(clientRegistration.getScopes())) {
				this.scope(clientRegistration.getScopes().toArray(new String[0]));
			}
			this.authorizationUri(clientRegistration.getProviderDetails().getAuthorizationUri());
			this.tokenUri(clientRegistration.getProviderDetails().getTokenUri());
			this.userInfoUri(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri());
			this.userNameAttributeName(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName());
			this.jwkSetUri(clientRegistration.getProviderDetails().getJwkSetUri());
			this.clientName(clientRegistration.getClientName());
		}

		public Builder clientId(String clientId) {
			this.clientId = clientId;
			return this;
		}

		public Builder clientSecret(String clientSecret) {
			this.clientSecret = clientSecret;
			return this;
		}

		public Builder clientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
			this.clientAuthenticationMethod = clientAuthenticationMethod;
			return this;
		}

		public Builder authorizationGrantType(AuthorizationGrantType authorizationGrantType) {
			this.authorizationGrantType = authorizationGrantType;
			return this;
		}

		public Builder redirectUri(String redirectUri) {
			this.redirectUri = redirectUri;
			return this;
		}

		public Builder scope(String... scope) {
			if (scope != null && scope.length > 0) {
				this.scopes = Collections.unmodifiableSet(
						new LinkedHashSet<>(Arrays.asList(scope)));
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

		public Builder userNameAttributeName(String userNameAttributeName) {
			this.userNameAttributeName = userNameAttributeName;
			return this;
		}

		public Builder jwkSetUri(String jwkSetUri) {
			this.jwkSetUri = jwkSetUri;
			return this;
		}

		public Builder clientName(String clientName) {
			this.clientName = clientName;
			return this;
		}

		public ClientRegistration build() {
			Assert.notNull(this.authorizationGrantType, "authorizationGrantType cannot be null");
			if (AuthorizationGrantType.IMPLICIT.equals(this.authorizationGrantType)) {
				this.validateImplicitGrantType();
			} else {
				this.validateAuthorizationCodeGrantType();
			}
			return this.create();
		}

		protected ClientRegistration create() {
			ClientRegistration clientRegistration = new ClientRegistration();

			clientRegistration.setRegistrationId(this.registrationId);
			clientRegistration.setClientId(this.clientId);
			clientRegistration.setClientSecret(this.clientSecret);
			clientRegistration.setClientAuthenticationMethod(this.clientAuthenticationMethod);
			clientRegistration.setAuthorizationGrantType(this.authorizationGrantType);
			clientRegistration.setRedirectUri(this.redirectUri);
			clientRegistration.setScopes(this.scopes);

			ProviderDetails providerDetails = clientRegistration.new ProviderDetails();
			providerDetails.setAuthorizationUri(this.authorizationUri);
			providerDetails.setTokenUri(this.tokenUri);
			providerDetails.getUserInfoEndpoint().setUri(this.userInfoUri);
			providerDetails.getUserInfoEndpoint().setUserNameAttributeName(this.userNameAttributeName);
			providerDetails.setJwkSetUri(this.jwkSetUri);
			clientRegistration.setProviderDetails(providerDetails);

			clientRegistration.setClientName(this.clientName);

			return clientRegistration;
		}

		protected void validateAuthorizationCodeGrantType() {
			Assert.isTrue(AuthorizationGrantType.AUTHORIZATION_CODE.equals(this.authorizationGrantType),
				"authorizationGrantType must be " + AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
			Assert.hasText(this.registrationId, "registrationId cannot be empty");
			Assert.hasText(this.clientId, "clientId cannot be empty");
			Assert.hasText(this.clientSecret, "clientSecret cannot be empty");
			Assert.notNull(this.clientAuthenticationMethod, "clientAuthenticationMethod cannot be null");
			Assert.hasText(this.redirectUri, "redirectUri cannot be empty");
			Assert.notEmpty(this.scopes, "scopes cannot be empty");
			Assert.hasText(this.authorizationUri, "authorizationUri cannot be empty");
			Assert.hasText(this.tokenUri, "tokenUri cannot be empty");
			if (this.scopes.contains(OidcScope.OPENID)) {
				// OIDC Clients need to verify/validate the ID Token
				Assert.hasText(this.jwkSetUri, "jwkSetUri cannot be empty");
			}
			Assert.hasText(this.clientName, "clientName cannot be empty");
		}

		protected void validateImplicitGrantType() {
			Assert.isTrue(AuthorizationGrantType.IMPLICIT.equals(this.authorizationGrantType),
				"authorizationGrantType must be " + AuthorizationGrantType.IMPLICIT.getValue());
			Assert.hasText(this.registrationId, "registrationId cannot be empty");
			Assert.hasText(this.clientId, "clientId cannot be empty");
			Assert.hasText(this.redirectUri, "redirectUri cannot be empty");
			Assert.notEmpty(this.scopes, "scopes cannot be empty");
			Assert.hasText(this.authorizationUri, "authorizationUri cannot be empty");
			Assert.hasText(this.clientName, "clientName cannot be empty");
		}
	}
}
