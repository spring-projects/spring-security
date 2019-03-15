/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.oauth2.client.registration;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A representation of a client registration with an OAuth 2.0 or OpenID Connect 1.0 Provider.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-2">Section 2 Client Registration</a>
 */
public final class ClientRegistration {
	private String registrationId;
	private String clientId;
	private String clientSecret;
	private ClientAuthenticationMethod clientAuthenticationMethod = ClientAuthenticationMethod.BASIC;
	private AuthorizationGrantType authorizationGrantType;
	private String redirectUriTemplate;
	private Set<String> scopes = Collections.emptySet();
	private ProviderDetails providerDetails = new ProviderDetails();
	private String clientName;

	private ClientRegistration() {
	}

	/**
	 * Returns the identifier for the registration.
	 *
	 * @return the identifier for the registration
	 */
	public String getRegistrationId() {
		return this.registrationId;
	}

	/**
	 * Returns the client identifier.
	 *
	 * @return the client identifier
	 */
	public String getClientId() {
		return this.clientId;
	}

	/**
	 * Returns the client secret.
	 *
	 * @return the client secret
	 */
	public String getClientSecret() {
		return this.clientSecret;
	}

	/**
	 * Returns the {@link ClientAuthenticationMethod authentication method} used
	 * when authenticating the client with the authorization server.
	 *
	 * @return the {@link ClientAuthenticationMethod}
	 */
	public ClientAuthenticationMethod getClientAuthenticationMethod() {
		return this.clientAuthenticationMethod;
	}

	/**
	 * Returns the {@link AuthorizationGrantType authorization grant type} used for the client.
	 *
	 * @return the {@link AuthorizationGrantType}
	 */
	public AuthorizationGrantType getAuthorizationGrantType() {
		return this.authorizationGrantType;
	}

	/**
	 * Returns the uri (or uri template) for the redirection endpoint.
	 *
	 * @return the uri for the redirection endpoint
	 */
	public String getRedirectUriTemplate() {
		return this.redirectUriTemplate;
	}

	/**
	 * Returns the scope(s) used for the client.
	 *
	 * @return the {@code Set} of scope(s)
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}

	/**
	 * Returns the details of the provider.
	 *
	 * @return the {@link ProviderDetails}
	 */
	public ProviderDetails getProviderDetails() {
		return this.providerDetails;
	}

	/**
	 * Returns the logical name of the client or registration.
	 *
	 * @return the client or registration name
	 */
	public String getClientName() {
		return this.clientName;
	}

	@Override
	public String toString() {
		return "ClientRegistration{"
			+ "registrationId='" + this.registrationId + '\''
			+ ", clientId='" + this.clientId + '\''
			+ ", clientSecret='" + this.clientSecret + '\''
			+ ", clientAuthenticationMethod=" + this.clientAuthenticationMethod
			+ ", authorizationGrantType=" + this.authorizationGrantType
			+ ", redirectUriTemplate='" + this.redirectUriTemplate + '\''
			+ ", scopes=" + this.scopes
			+ ", providerDetails=" + this.providerDetails
			+ ", clientName='" + this.clientName
			+ '\'' + '}';
	}

	/**
	 * Details of the Provider.
	 */
	public class ProviderDetails {
		private String authorizationUri;
		private String tokenUri;
		private UserInfoEndpoint userInfoEndpoint = new UserInfoEndpoint();
		private String jwkSetUri;

		private ProviderDetails() {
		}

		/**
		 * Returns the uri for the authorization endpoint.
		 *
		 * @return the uri for the authorization endpoint
		 */
		public String getAuthorizationUri() {
			return this.authorizationUri;
		}

		/**
		 * Returns the uri for the token endpoint.
		 *
		 * @return the uri for the token endpoint
		 */
		public String getTokenUri() {
			return this.tokenUri;
		}

		/**
		 * Returns the details of the {@link UserInfoEndpoint UserInfo Endpoint}.
		 *
		 * @return the {@link UserInfoEndpoint}
		 */
		public UserInfoEndpoint getUserInfoEndpoint() {
			return this.userInfoEndpoint;
		}

		/**
		 * Returns the uri for the JSON Web Key (JWK) Set endpoint.
		 *
		 * @return the uri for the JSON Web Key (JWK) Set endpoint
		 */
		public String getJwkSetUri() {
			return this.jwkSetUri;
		}

		/**
		 * Details of the UserInfo Endpoint.
		 */
		public class UserInfoEndpoint {
			private String uri;
			private String userNameAttributeName;

			private UserInfoEndpoint() {
			}

			/**
			 * Returns the uri for the user info endpoint.
			 *
			 * @return the uri for the user info endpoint
			 */
			public String getUri() {
				return this.uri;
			}

			/**
			 * Returns the attribute name used to access the user's name from the user info response.
			 *
			 * @return the attribute name used to access the user's name from the user info response
			 */
			public String getUserNameAttributeName() {
				return this.userNameAttributeName;
			}
		}
	}

	/**
	 * Returns a new {@link Builder}, initialized with the provided registration identifier.
	 *
	 * @param registrationId the identifier for the registration
	 * @return the {@link Builder}
	 */
	public static Builder withRegistrationId(String registrationId) {
		Assert.hasText(registrationId, "registrationId cannot be empty");
		return new Builder(registrationId);
	}

	/**
	 * A builder for {@link ClientRegistration}.
	 */
	public static class Builder {
		private String registrationId;
		private String clientId;
		private String clientSecret;
		private ClientAuthenticationMethod clientAuthenticationMethod = ClientAuthenticationMethod.BASIC;
		private AuthorizationGrantType authorizationGrantType;
		private String redirectUriTemplate;
		private Set<String> scopes;
		private String authorizationUri;
		private String tokenUri;
		private String userInfoUri;
		private String userNameAttributeName;
		private String jwkSetUri;
		private String clientName;

		private Builder(String registrationId) {
			this.registrationId = registrationId;
		}

		/**
		 * Sets the client identifier.
		 *
		 * @param clientId the client identifier
		 * @return the {@link Builder}
		 */
		public Builder clientId(String clientId) {
			this.clientId = clientId;
			return this;
		}

		/**
		 * Sets the client secret.
		 *
		 * @param clientSecret the client secret
		 * @return the {@link Builder}
		 */
		public Builder clientSecret(String clientSecret) {
			this.clientSecret = clientSecret;
			return this;
		}

		/**
		 * Sets the {@link ClientAuthenticationMethod authentication method} used
		 * when authenticating the client with the authorization server.
		 *
		 * @param clientAuthenticationMethod the authentication method used for the client
		 * @return the {@link Builder}
		 */
		public Builder clientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
			this.clientAuthenticationMethod = clientAuthenticationMethod;
			return this;
		}

		/**
		 * Sets the {@link AuthorizationGrantType authorization grant type} used for the client.
		 *
		 * @param authorizationGrantType the authorization grant type used for the client
		 * @return the {@link Builder}
		 */
		public Builder authorizationGrantType(AuthorizationGrantType authorizationGrantType) {
			this.authorizationGrantType = authorizationGrantType;
			return this;
		}

		/**
		 * Sets the uri (or uri template) for the redirection endpoint.
		 *
		 * @param redirectUriTemplate the uri for the redirection endpoint
		 * @return the {@link Builder}
		 */
		public Builder redirectUriTemplate(String redirectUriTemplate) {
			this.redirectUriTemplate = redirectUriTemplate;
			return this;
		}

		/**
		 * Sets the scope(s) used for the client.
		 *
		 * @param scope the scope(s) used for the client
		 * @return the {@link Builder}
		 */
		public Builder scope(String... scope) {
			if (scope != null && scope.length > 0) {
				this.scopes = Collections.unmodifiableSet(
						new LinkedHashSet<>(Arrays.asList(scope)));
			}
			return this;
		}

		/**
		 * Sets the uri for the authorization endpoint.
		 *
		 * @param authorizationUri the uri for the authorization endpoint
		 * @return the {@link Builder}
		 */
		public Builder authorizationUri(String authorizationUri) {
			this.authorizationUri = authorizationUri;
			return this;
		}

		/**
		 * Sets the uri for the token endpoint.
		 *
		 * @param tokenUri the uri for the token endpoint
		 * @return the {@link Builder}
		 */
		public Builder tokenUri(String tokenUri) {
			this.tokenUri = tokenUri;
			return this;
		}

		/**
		 * Sets the uri for the user info endpoint.
		 *
		 * @param userInfoUri the uri for the user info endpoint
		 * @return the {@link Builder}
		 */
		public Builder userInfoUri(String userInfoUri) {
			this.userInfoUri = userInfoUri;
			return this;
		}

		/**
		 * Sets the attribute name used to access the user's name from the user info response.
		 *
		 * @param userNameAttributeName the attribute name used to access the user's name from the user info response
		 * @return the {@link Builder}
		 */
		public Builder userNameAttributeName(String userNameAttributeName) {
			this.userNameAttributeName = userNameAttributeName;
			return this;
		}

		/**
		 * Sets the uri for the JSON Web Key (JWK) Set endpoint.
		 *
		 * @param jwkSetUri the uri for the JSON Web Key (JWK) Set endpoint
		 * @return the {@link Builder}
		 */
		public Builder jwkSetUri(String jwkSetUri) {
			this.jwkSetUri = jwkSetUri;
			return this;
		}

		/**
		 * Sets the logical name of the client or registration.
		 *
		 * @param clientName the client or registration name
		 * @return the {@link Builder}
		 */
		public Builder clientName(String clientName) {
			this.clientName = clientName;
			return this;
		}

		/**
		 * Builds a new {@link ClientRegistration}.
		 *
		 * @return a {@link ClientRegistration}
		 */
		public ClientRegistration build() {
			Assert.notNull(this.authorizationGrantType, "authorizationGrantType cannot be null");
			if (AuthorizationGrantType.IMPLICIT.equals(this.authorizationGrantType)) {
				this.validateImplicitGrantType();
			} else {
				this.validateAuthorizationCodeGrantType();
			}
			return this.create();
		}

		private ClientRegistration create() {
			ClientRegistration clientRegistration = new ClientRegistration();

			clientRegistration.registrationId = this.registrationId;
			clientRegistration.clientId = this.clientId;
			clientRegistration.clientSecret = this.clientSecret;
			clientRegistration.clientAuthenticationMethod = this.clientAuthenticationMethod;
			clientRegistration.authorizationGrantType = this.authorizationGrantType;
			clientRegistration.redirectUriTemplate = this.redirectUriTemplate;
			clientRegistration.scopes = this.scopes;

			ProviderDetails providerDetails = clientRegistration.new ProviderDetails();
			providerDetails.authorizationUri = this.authorizationUri;
			providerDetails.tokenUri = this.tokenUri;
			providerDetails.userInfoEndpoint.uri = this.userInfoUri;
			providerDetails.userInfoEndpoint.userNameAttributeName = this.userNameAttributeName;
			providerDetails.jwkSetUri = this.jwkSetUri;
			clientRegistration.providerDetails = providerDetails;

			clientRegistration.clientName = this.clientName;

			return clientRegistration;
		}

		private void validateAuthorizationCodeGrantType() {
			Assert.isTrue(AuthorizationGrantType.AUTHORIZATION_CODE.equals(this.authorizationGrantType),
				"authorizationGrantType must be " + AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
			Assert.hasText(this.registrationId, "registrationId cannot be empty");
			Assert.hasText(this.clientId, "clientId cannot be empty");
			Assert.hasText(this.clientSecret, "clientSecret cannot be empty");
			Assert.notNull(this.clientAuthenticationMethod, "clientAuthenticationMethod cannot be null");
			Assert.hasText(this.redirectUriTemplate, "redirectUriTemplate cannot be empty");
			Assert.notEmpty(this.scopes, "scopes cannot be empty");
			Assert.hasText(this.authorizationUri, "authorizationUri cannot be empty");
			Assert.hasText(this.tokenUri, "tokenUri cannot be empty");
			if (this.scopes.contains(OidcScopes.OPENID)) {
				// OIDC Clients need to verify/validate the ID Token
				Assert.hasText(this.jwkSetUri, "jwkSetUri cannot be empty");
			}
			Assert.hasText(this.clientName, "clientName cannot be empty");
		}

		private void validateImplicitGrantType() {
			Assert.isTrue(AuthorizationGrantType.IMPLICIT.equals(this.authorizationGrantType),
				"authorizationGrantType must be " + AuthorizationGrantType.IMPLICIT.getValue());
			Assert.hasText(this.registrationId, "registrationId cannot be empty");
			Assert.hasText(this.clientId, "clientId cannot be empty");
			Assert.hasText(this.redirectUriTemplate, "redirectUriTemplate cannot be empty");
			Assert.notEmpty(this.scopes, "scopes cannot be empty");
			Assert.hasText(this.authorizationUri, "authorizationUri cannot be empty");
			Assert.hasText(this.clientName, "clientName cannot be empty");
		}
	}
}
