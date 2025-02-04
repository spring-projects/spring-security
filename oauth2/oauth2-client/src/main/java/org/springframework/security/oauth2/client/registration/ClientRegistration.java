/*
 * Copyright 2002-2025 the original author or authors.
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

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A representation of a client registration with an OAuth 2.0 or OpenID Connect 1.0
 * Provider.
 *
 * @author Joe Grandja
 * @author Michael Sosa
 * @since 5.0
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-2">Section 2
 * Client Registration</a>
 */
public final class ClientRegistration implements Serializable {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private String registrationId;

	private String clientId;

	private String clientSecret;

	private ClientAuthenticationMethod clientAuthenticationMethod;

	private AuthorizationGrantType authorizationGrantType;

	private String redirectUri;

	private Set<String> scopes = Collections.emptySet();

	private ProviderDetails providerDetails = new ProviderDetails();

	private String clientName;

	private ClientSettings clientSettings;

	private ClientRegistration() {
	}

	/**
	 * Returns the identifier for the registration.
	 * @return the identifier for the registration
	 */
	public String getRegistrationId() {
		return this.registrationId;
	}

	/**
	 * Returns the client identifier.
	 * @return the client identifier
	 */
	public String getClientId() {
		return this.clientId;
	}

	/**
	 * Returns the client secret.
	 * @return the client secret
	 */
	public String getClientSecret() {
		return this.clientSecret;
	}

	/**
	 * Returns the {@link ClientAuthenticationMethod authentication method} used when
	 * authenticating the client with the authorization server.
	 * @return the {@link ClientAuthenticationMethod}
	 */
	public ClientAuthenticationMethod getClientAuthenticationMethod() {
		return this.clientAuthenticationMethod;
	}

	/**
	 * Returns the {@link AuthorizationGrantType authorization grant type} used for the
	 * client.
	 * @return the {@link AuthorizationGrantType}
	 */
	public AuthorizationGrantType getAuthorizationGrantType() {
		return this.authorizationGrantType;
	}

	/**
	 * Returns the uri (or uri template) for the redirection endpoint.
	 *
	 * <br />
	 * The supported uri template variables are: {baseScheme}, {baseHost}, {basePort},
	 * {basePath} and {registrationId}.
	 *
	 * <br />
	 * <b>NOTE:</b> {baseUrl} is also supported, which is the same as
	 * {baseScheme}://{baseHost}{basePort}{basePath}.
	 *
	 * <br />
	 * Configuring uri template variables is especially useful when the client is running
	 * behind a Proxy Server. This ensures that the X-Forwarded-* headers are used when
	 * expanding the redirect-uri.
	 * @return the uri (or uri template) for the redirection endpoint
	 * @since 5.4
	 */
	public String getRedirectUri() {
		return this.redirectUri;
	}

	/**
	 * Returns the scope(s) used for the client.
	 * @return the {@code Set} of scope(s)
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}

	/**
	 * Returns the details of the provider.
	 * @return the {@link ProviderDetails}
	 */
	public ProviderDetails getProviderDetails() {
		return this.providerDetails;
	}

	/**
	 * Returns the logical name of the client or registration.
	 * @return the client or registration name
	 */
	public String getClientName() {
		return this.clientName;
	}

	/**
	 * Returns the {@link ClientSettings client configuration settings}.
	 * @return the {@link ClientSettings}
	 */
	public ClientSettings getClientSettings() {
		return this.clientSettings;
	}

	@Override
	public String toString() {
		// @formatter:off
		return "ClientRegistration{"
				+ "registrationId='" + this.registrationId + '\''
				+ ", clientId='" + this.clientId + '\''
				+ ", clientSecret='" + this.clientSecret + '\''
				+ ", clientAuthenticationMethod=" + this.clientAuthenticationMethod
				+ ", authorizationGrantType=" + this.authorizationGrantType
				+ ", redirectUri='" + this.redirectUri
				+ '\'' + ", scopes=" + this.scopes
				+ ", providerDetails=" + this.providerDetails
				+ ", clientName='" + this.clientName + '\''
				+ ", clientSettings='" + this.clientSettings + '\''
				+ '}';
		// @formatter:on
	}

	/**
	 * Returns a new {@link Builder}, initialized with the provided registration
	 * identifier.
	 * @param registrationId the identifier for the registration
	 * @return the {@link Builder}
	 */
	public static Builder withRegistrationId(String registrationId) {
		Assert.hasText(registrationId, "registrationId cannot be empty");
		return new Builder(registrationId);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the provided
	 * {@link ClientRegistration}.
	 * @param clientRegistration the {@link ClientRegistration} to copy from
	 * @return the {@link Builder}
	 */
	public static Builder withClientRegistration(ClientRegistration clientRegistration) {
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		return new Builder(clientRegistration);
	}

	/**
	 * Details of the Provider.
	 */
	public class ProviderDetails implements Serializable {

		private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

		private String authorizationUri;

		private String tokenUri;

		private UserInfoEndpoint userInfoEndpoint = new UserInfoEndpoint();

		private String jwkSetUri;

		private String issuerUri;

		private Map<String, Object> configurationMetadata = Collections.emptyMap();

		ProviderDetails() {
		}

		/**
		 * Returns the uri for the authorization endpoint.
		 * @return the uri for the authorization endpoint
		 */
		public String getAuthorizationUri() {
			return this.authorizationUri;
		}

		/**
		 * Returns the uri for the token endpoint.
		 * @return the uri for the token endpoint
		 */
		public String getTokenUri() {
			return this.tokenUri;
		}

		/**
		 * Returns the details of the {@link UserInfoEndpoint UserInfo Endpoint}.
		 * @return the {@link UserInfoEndpoint}
		 */
		public UserInfoEndpoint getUserInfoEndpoint() {
			return this.userInfoEndpoint;
		}

		/**
		 * Returns the uri for the JSON Web Key (JWK) Set endpoint.
		 * @return the uri for the JSON Web Key (JWK) Set endpoint
		 */
		public String getJwkSetUri() {
			return this.jwkSetUri;
		}

		/**
		 * Returns the issuer identifier uri for the OpenID Connect 1.0 provider or the
		 * OAuth 2.0 Authorization Server.
		 * @return the issuer identifier uri for the OpenID Connect 1.0 provider or the
		 * OAuth 2.0 Authorization Server
		 * @since 5.4
		 */
		public String getIssuerUri() {
			return this.issuerUri;
		}

		/**
		 * Returns a {@code Map} of the metadata describing the provider's configuration.
		 * @return a {@code Map} of the metadata describing the provider's configuration
		 * @since 5.1
		 */
		public Map<String, Object> getConfigurationMetadata() {
			return this.configurationMetadata;
		}

		/**
		 * Details of the UserInfo Endpoint.
		 */
		public class UserInfoEndpoint implements Serializable {

			private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

			private String uri;

			private AuthenticationMethod authenticationMethod = AuthenticationMethod.HEADER;

			private String userNameAttributeName;

			UserInfoEndpoint() {
			}

			/**
			 * Returns the uri for the user info endpoint.
			 * @return the uri for the user info endpoint
			 */
			public String getUri() {
				return this.uri;
			}

			/**
			 * Returns the authentication method for the user info endpoint.
			 * @return the {@link AuthenticationMethod} for the user info endpoint.
			 * @since 5.1
			 */
			public AuthenticationMethod getAuthenticationMethod() {
				return this.authenticationMethod;
			}

			/**
			 * Returns the attribute name used to access the user's name from the user
			 * info response.
			 * @return the attribute name used to access the user's name from the user
			 * info response
			 */
			public String getUserNameAttributeName() {
				return this.userNameAttributeName;
			}

		}

	}

	/**
	 * A builder for {@link ClientRegistration}.
	 */
	public static final class Builder implements Serializable {

		private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

		private static final Log logger = LogFactory.getLog(Builder.class);

		private static final List<AuthorizationGrantType> AUTHORIZATION_GRANT_TYPES = Arrays.asList(
				AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.CLIENT_CREDENTIALS,
				AuthorizationGrantType.REFRESH_TOKEN, AuthorizationGrantType.PASSWORD);

		private String registrationId;

		private String clientId;

		private String clientSecret;

		private ClientAuthenticationMethod clientAuthenticationMethod;

		private AuthorizationGrantType authorizationGrantType;

		private String redirectUri;

		private Set<String> scopes;

		private String authorizationUri;

		private String tokenUri;

		private String userInfoUri;

		private AuthenticationMethod userInfoAuthenticationMethod = AuthenticationMethod.HEADER;

		private String userNameAttributeName;

		private String jwkSetUri;

		private String issuerUri;

		private Map<String, Object> configurationMetadata = Collections.emptyMap();

		private String clientName;

		private ClientSettings clientSettings = ClientSettings.builder().build();

		private Builder(String registrationId) {
			this.registrationId = registrationId;
		}

		private Builder(ClientRegistration clientRegistration) {
			this.registrationId = clientRegistration.registrationId;
			this.clientId = clientRegistration.clientId;
			this.clientSecret = clientRegistration.clientSecret;
			this.clientAuthenticationMethod = clientRegistration.clientAuthenticationMethod;
			this.authorizationGrantType = clientRegistration.authorizationGrantType;
			this.redirectUri = clientRegistration.redirectUri;
			this.scopes = (clientRegistration.scopes != null) ? new HashSet<>(clientRegistration.scopes) : null;
			this.authorizationUri = clientRegistration.providerDetails.authorizationUri;
			this.tokenUri = clientRegistration.providerDetails.tokenUri;
			this.userInfoUri = clientRegistration.providerDetails.userInfoEndpoint.uri;
			this.userInfoAuthenticationMethod = clientRegistration.providerDetails.userInfoEndpoint.authenticationMethod;
			this.userNameAttributeName = clientRegistration.providerDetails.userInfoEndpoint.userNameAttributeName;
			this.jwkSetUri = clientRegistration.providerDetails.jwkSetUri;
			this.issuerUri = clientRegistration.providerDetails.issuerUri;
			Map<String, Object> configurationMetadata = clientRegistration.providerDetails.configurationMetadata;
			if (configurationMetadata != Collections.EMPTY_MAP) {
				this.configurationMetadata = new HashMap<>(configurationMetadata);
			}
			this.clientName = clientRegistration.clientName;
			this.clientSettings = clientRegistration.clientSettings;
		}

		/**
		 * Sets the registration id.
		 * @param registrationId the registration id
		 * @return the {@link Builder}
		 */
		public Builder registrationId(String registrationId) {
			this.registrationId = registrationId;
			return this;
		}

		/**
		 * Sets the client identifier.
		 * @param clientId the client identifier
		 * @return the {@link Builder}
		 */
		public Builder clientId(String clientId) {
			this.clientId = clientId;
			return this;
		}

		/**
		 * Sets the client secret.
		 * @param clientSecret the client secret
		 * @return the {@link Builder}
		 */
		public Builder clientSecret(String clientSecret) {
			this.clientSecret = clientSecret;
			return this;
		}

		/**
		 * Sets the {@link ClientAuthenticationMethod authentication method} used when
		 * authenticating the client with the authorization server.
		 * @param clientAuthenticationMethod the authentication method used for the client
		 * @return the {@link Builder}
		 */
		public Builder clientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
			this.clientAuthenticationMethod = clientAuthenticationMethod;
			return this;
		}

		/**
		 * Sets the {@link AuthorizationGrantType authorization grant type} used for the
		 * client.
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
		 * <br />
		 * The supported uri template variables are: {baseScheme}, {baseHost}, {basePort},
		 * {basePath} and {registrationId}.
		 *
		 * <br />
		 * <b>NOTE:</b> {baseUrl} is also supported, which is the same as
		 * {baseScheme}://{baseHost}{basePort}{basePath}.
		 *
		 * <br />
		 * Configuring uri template variables is especially useful when the client is
		 * running behind a Proxy Server. This ensures that the X-Forwarded-* headers are
		 * used when expanding the redirect-uri.
		 * @param redirectUri the uri (or uri template) for the redirection endpoint
		 * @return the {@link Builder}
		 * @since 5.4
		 */
		public Builder redirectUri(String redirectUri) {
			this.redirectUri = redirectUri;
			return this;
		}

		/**
		 * Sets the scope(s) used for the client.
		 * @param scope the scope(s) used for the client
		 * @return the {@link Builder}
		 */
		public Builder scope(String... scope) {
			if (scope != null && scope.length > 0) {
				this.scopes = Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList(scope)));
			}
			return this;
		}

		/**
		 * Sets the scope(s) used for the client.
		 * @param scope the scope(s) used for the client
		 * @return the {@link Builder}
		 */
		public Builder scope(Collection<String> scope) {
			if (scope != null && !scope.isEmpty()) {
				this.scopes = Collections.unmodifiableSet(new LinkedHashSet<>(scope));
			}
			return this;
		}

		/**
		 * Sets the uri for the authorization endpoint.
		 * @param authorizationUri the uri for the authorization endpoint
		 * @return the {@link Builder}
		 */
		public Builder authorizationUri(String authorizationUri) {
			this.authorizationUri = authorizationUri;
			return this;
		}

		/**
		 * Sets the uri for the token endpoint.
		 * @param tokenUri the uri for the token endpoint
		 * @return the {@link Builder}
		 */
		public Builder tokenUri(String tokenUri) {
			this.tokenUri = tokenUri;
			return this;
		}

		/**
		 * Sets the uri for the user info endpoint.
		 * @param userInfoUri the uri for the user info endpoint
		 * @return the {@link Builder}
		 */
		public Builder userInfoUri(String userInfoUri) {
			this.userInfoUri = userInfoUri;
			return this;
		}

		/**
		 * Sets the authentication method for the user info endpoint.
		 * @param userInfoAuthenticationMethod the authentication method for the user info
		 * endpoint
		 * @return the {@link Builder}
		 * @since 5.1
		 */
		public Builder userInfoAuthenticationMethod(AuthenticationMethod userInfoAuthenticationMethod) {
			this.userInfoAuthenticationMethod = userInfoAuthenticationMethod;
			return this;
		}

		/**
		 * Sets the attribute name used to access the user's name from the user info
		 * response.
		 * @param userNameAttributeName the attribute name used to access the user's name
		 * from the user info response
		 * @return the {@link Builder}
		 */
		public Builder userNameAttributeName(String userNameAttributeName) {
			this.userNameAttributeName = userNameAttributeName;
			return this;
		}

		/**
		 * Sets the uri for the JSON Web Key (JWK) Set endpoint.
		 * @param jwkSetUri the uri for the JSON Web Key (JWK) Set endpoint
		 * @return the {@link Builder}
		 */
		public Builder jwkSetUri(String jwkSetUri) {
			this.jwkSetUri = jwkSetUri;
			return this;
		}

		/**
		 * Sets the issuer identifier uri for the OpenID Connect 1.0 provider or the OAuth
		 * 2.0 Authorization Server.
		 * @param issuerUri the issuer identifier uri for the OpenID Connect 1.0 provider
		 * or the OAuth 2.0 Authorization Server
		 * @return the {@link Builder}
		 * @since 5.4
		 */
		public Builder issuerUri(String issuerUri) {
			this.issuerUri = issuerUri;
			return this;
		}

		/**
		 * Sets the metadata describing the provider's configuration.
		 * @param configurationMetadata the metadata describing the provider's
		 * configuration
		 * @return the {@link Builder}
		 * @since 5.1
		 */
		public Builder providerConfigurationMetadata(Map<String, Object> configurationMetadata) {
			if (configurationMetadata != null) {
				this.configurationMetadata = new LinkedHashMap<>(configurationMetadata);
			}
			return this;
		}

		/**
		 * Sets the logical name of the client or registration.
		 * @param clientName the client or registration name
		 * @return the {@link Builder}
		 */
		public Builder clientName(String clientName) {
			this.clientName = clientName;
			return this;
		}

		/**
		 * Sets the {@link ClientSettings client configuration settings}.
		 * @param clientSettings the client configuration settings
		 * @return the {@link Builder}
		 */
		public Builder clientSettings(ClientSettings clientSettings) {
			Assert.notNull(clientSettings, "clientSettings cannot be null");
			this.clientSettings = clientSettings;
			return this;
		}

		/**
		 * Builds a new {@link ClientRegistration}.
		 * @return a {@link ClientRegistration}
		 */
		public ClientRegistration build() {
			Assert.notNull(this.authorizationGrantType, "authorizationGrantType cannot be null");
			if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(this.authorizationGrantType)) {
				this.validateClientCredentialsGrantType();
			}
			else if (AuthorizationGrantType.PASSWORD.equals(this.authorizationGrantType)) {
				this.validatePasswordGrantType();
			}
			else if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(this.authorizationGrantType)) {
				this.validateAuthorizationCodeGrantType();
			}
			this.validateAuthorizationGrantTypes();
			this.validateScopes();
			return this.create();
		}

		private ClientRegistration create() {
			ClientRegistration clientRegistration = new ClientRegistration();
			clientRegistration.registrationId = this.registrationId;
			clientRegistration.clientId = this.clientId;
			clientRegistration.clientSecret = StringUtils.hasText(this.clientSecret) ? this.clientSecret : "";
			clientRegistration.clientAuthenticationMethod = (this.clientAuthenticationMethod != null)
					? this.clientAuthenticationMethod : deduceClientAuthenticationMethod(clientRegistration);
			clientRegistration.authorizationGrantType = this.authorizationGrantType;
			clientRegistration.redirectUri = this.redirectUri;
			clientRegistration.scopes = this.scopes;
			clientRegistration.providerDetails = createProviderDetails(clientRegistration);
			clientRegistration.clientName = StringUtils.hasText(this.clientName) ? this.clientName
					: this.registrationId;
			clientRegistration.clientSettings = this.clientSettings;
			return clientRegistration;
		}

		private ClientAuthenticationMethod deduceClientAuthenticationMethod(ClientRegistration clientRegistration) {
			if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(this.authorizationGrantType)
					&& (!StringUtils.hasText(this.clientSecret))) {
				return ClientAuthenticationMethod.NONE;
			}
			return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
		}

		private ProviderDetails createProviderDetails(ClientRegistration clientRegistration) {
			ProviderDetails providerDetails = clientRegistration.new ProviderDetails();
			providerDetails.authorizationUri = this.authorizationUri;
			providerDetails.tokenUri = this.tokenUri;
			providerDetails.userInfoEndpoint.uri = this.userInfoUri;
			providerDetails.userInfoEndpoint.authenticationMethod = this.userInfoAuthenticationMethod;
			providerDetails.userInfoEndpoint.userNameAttributeName = this.userNameAttributeName;
			providerDetails.jwkSetUri = this.jwkSetUri;
			providerDetails.issuerUri = this.issuerUri;
			providerDetails.configurationMetadata = Collections.unmodifiableMap(this.configurationMetadata);
			return providerDetails;
		}

		private void validateAuthorizationCodeGrantType() {
			Assert.isTrue(AuthorizationGrantType.AUTHORIZATION_CODE.equals(this.authorizationGrantType),
					() -> "authorizationGrantType must be " + AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
			Assert.hasText(this.registrationId, "registrationId cannot be empty");
			Assert.hasText(this.clientId, "clientId cannot be empty");
			Assert.hasText(this.redirectUri, "redirectUri cannot be empty");
			Assert.hasText(this.authorizationUri, "authorizationUri cannot be empty");
			Assert.hasText(this.tokenUri, "tokenUri cannot be empty");
		}

		private void validateClientCredentialsGrantType() {
			Assert.isTrue(AuthorizationGrantType.CLIENT_CREDENTIALS.equals(this.authorizationGrantType),
					() -> "authorizationGrantType must be " + AuthorizationGrantType.CLIENT_CREDENTIALS.getValue());
			Assert.hasText(this.registrationId, "registrationId cannot be empty");
			Assert.hasText(this.clientId, "clientId cannot be empty");
			Assert.hasText(this.tokenUri, "tokenUri cannot be empty");
		}

		private void validatePasswordGrantType() {
			Assert.isTrue(AuthorizationGrantType.PASSWORD.equals(this.authorizationGrantType),
					() -> "authorizationGrantType must be " + AuthorizationGrantType.PASSWORD.getValue());
			Assert.hasText(this.registrationId, "registrationId cannot be empty");
			Assert.hasText(this.clientId, "clientId cannot be empty");
			Assert.hasText(this.tokenUri, "tokenUri cannot be empty");
		}

		private void validateAuthorizationGrantTypes() {
			for (AuthorizationGrantType authorizationGrantType : AUTHORIZATION_GRANT_TYPES) {
				if (authorizationGrantType.getValue().equalsIgnoreCase(this.authorizationGrantType.getValue())
						&& !authorizationGrantType.equals(this.authorizationGrantType)) {
					logger.warn(LogMessage.format(
							"AuthorizationGrantType: %s does not match the pre-defined constant %s and won't match a valid OAuth2AuthorizedClientProvider",
							this.authorizationGrantType, authorizationGrantType));
				}
				if (!AuthorizationGrantType.AUTHORIZATION_CODE.equals(this.authorizationGrantType)
						&& this.clientSettings.isRequireProofKey()) {
					throw new IllegalStateException(
							"clientSettings.isRequireProofKey=true is only valid with authorizationGrantType=AUTHORIZATION_CODE. Got authorizationGrantType="
									+ this.authorizationGrantType);
				}
			}
		}

		private void validateScopes() {
			if (this.scopes == null) {
				return;
			}
			for (String scope : this.scopes) {
				Assert.isTrue(validateScope(scope), "scope \"" + scope + "\" contains invalid characters");
			}
		}

		private static boolean validateScope(String scope) {
			return scope == null || scope.chars()
				.allMatch((c) -> withinTheRangeOf(c, 0x21, 0x21) || withinTheRangeOf(c, 0x23, 0x5B)
						|| withinTheRangeOf(c, 0x5D, 0x7E));
		}

		private static boolean withinTheRangeOf(int c, int min, int max) {
			return c >= min && c <= max;
		}

	}

	/**
	 * A facility for client configuration settings.
	 *
	 * @author DingHao
	 * @since 6.5
	 */
	public static final class ClientSettings {

		private boolean requireProofKey;

		private ClientSettings() {

		}

		public boolean isRequireProofKey() {
			return this.requireProofKey;
		}

		@Override
		public boolean equals(Object o) {
			if (this == o) {
				return true;
			}
			if (!(o instanceof ClientSettings that)) {
				return false;
			}
			return this.requireProofKey == that.requireProofKey;
		}

		@Override
		public int hashCode() {
			return Objects.hashCode(this.requireProofKey);
		}

		@Override
		public String toString() {
			return "ClientSettings{" + "requireProofKey=" + this.requireProofKey + '}';
		}

		public static Builder builder() {
			return new Builder();
		}

		public static final class Builder {

			private boolean requireProofKey;

			private Builder() {
			}

			/**
			 * Set to {@code true} if the client is required to provide a proof key
			 * challenge and verifier when performing the Authorization Code Grant flow.
			 * @param requireProofKey {@code true} if the client is required to provide a
			 * proof key challenge and verifier, {@code false} otherwise
			 * @return the {@link Builder} for further configuration
			 */
			public Builder requireProofKey(boolean requireProofKey) {
				this.requireProofKey = requireProofKey;
				return this;
			}

			public ClientSettings build() {
				ClientSettings clientSettings = new ClientSettings();
				clientSettings.requireProofKey = this.requireProofKey;
				return clientSettings;
			}

		}

	}

}
