/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.oauth2.core.endpoint;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A representation of an OAuth 2.0 Authorization Request
 * for the authorization code grant type or implicit grant type.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AuthorizationGrantType
 * @see OAuth2AuthorizationResponseType
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Code Grant Request</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.2.1">Section 4.2.1 Implicit Grant Request</a>
 */
public final class OAuth2AuthorizationRequest implements Serializable {
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
	private String authorizationUri;
	private AuthorizationGrantType authorizationGrantType;
	private OAuth2AuthorizationResponseType responseType;
	private String clientId;
	private String redirectUri;
	private Set<String> scopes;
	private String state;
	private Map<String, Object> additionalParameters;
	private String authorizationRequestUri;

	private OAuth2AuthorizationRequest() {
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
	 * Returns the {@link AuthorizationGrantType grant type}.
	 *
	 * @return the {@link AuthorizationGrantType}
	 */
	public AuthorizationGrantType getGrantType() {
		return this.authorizationGrantType;
	}

	/**
	 * Returns the {@link OAuth2AuthorizationResponseType response type}.
	 *
	 * @return the {@link OAuth2AuthorizationResponseType}
	 */
	public OAuth2AuthorizationResponseType getResponseType() {
		return this.responseType;
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
	 * Returns the uri for the redirection endpoint.
	 *
	 * @return the uri for the redirection endpoint
	 */
	public String getRedirectUri() {
		return this.redirectUri;
	}

	/**
	 * Returns the scope(s).
	 *
	 * @return the scope(s)
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}

	/**
	 * Returns the state.
	 *
	 * @return the state
	 */
	public String getState() {
		return this.state;
	}

	/**
	 * Returns the additional parameters used in the request.
	 *
	 * @return a {@code Map} of the additional parameters used in the request
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

	/**
	 * Returns the {@code URI} string representation of the OAuth 2.0 Authorization Request.
	 *
	 * <p>
	 * <b>NOTE:</b> The {@code URI} string is encoded in the
	 * {@code application/x-www-form-urlencoded} MIME format.
	 *
	 * @since 5.1
	 * @return the {@code URI} string representation of the OAuth 2.0 Authorization Request
	 */
	public String getAuthorizationRequestUri() {
		return this.authorizationRequestUri;
	}

	/**
	 * Returns a new {@link Builder}, initialized with the authorization code grant type.
	 *
	 * @return the {@link Builder}
	 */
	public static Builder authorizationCode() {
		return new Builder(AuthorizationGrantType.AUTHORIZATION_CODE);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the implicit grant type.
	 *
	 * @return the {@link Builder}
	 */
	public static Builder implicit() {
		return new Builder(AuthorizationGrantType.IMPLICIT);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the values
	 * from the provided {@code authorizationRequest}.
	 *
	 * @since 5.1
	 * @param authorizationRequest the authorization request used for initializing the {@link Builder}
	 * @return the {@link Builder}
	 */
	public static Builder from(OAuth2AuthorizationRequest authorizationRequest) {
		Assert.notNull(authorizationRequest, "authorizationRequest cannot be null");

		return new Builder(authorizationRequest.getGrantType())
				.authorizationUri(authorizationRequest.getAuthorizationUri())
				.clientId(authorizationRequest.getClientId())
				.redirectUri(authorizationRequest.getRedirectUri())
				.scopes(authorizationRequest.getScopes())
				.state(authorizationRequest.getState())
				.additionalParameters(authorizationRequest.getAdditionalParameters());
	}

	/**
	 * A builder for {@link OAuth2AuthorizationRequest}.
	 */
	public static class Builder {
		private String authorizationUri;
		private AuthorizationGrantType authorizationGrantType;
		private OAuth2AuthorizationResponseType responseType;
		private String clientId;
		private String redirectUri;
		private Set<String> scopes;
		private String state;
		private Map<String, Object> additionalParameters;
		private String authorizationRequestUri;

		private Builder(AuthorizationGrantType authorizationGrantType) {
			Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
			this.authorizationGrantType = authorizationGrantType;
			if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)) {
				this.responseType = OAuth2AuthorizationResponseType.CODE;
			} else if (AuthorizationGrantType.IMPLICIT.equals(authorizationGrantType)) {
				this.responseType = OAuth2AuthorizationResponseType.TOKEN;
			}
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
		 * Sets the uri for the redirection endpoint.
		 *
		 * @param redirectUri the uri for the redirection endpoint
		 * @return the {@link Builder}
		 */
		public Builder redirectUri(String redirectUri) {
			this.redirectUri = redirectUri;
			return this;
		}

		/**
		 * Sets the scope(s).
		 *
		 * @param scope the scope(s)
		 * @return the {@link Builder}
		 */
		public Builder scope(String... scope) {
			if (scope != null && scope.length > 0) {
				return this.scopes(Arrays.stream(scope).collect(
					Collectors.toCollection(LinkedHashSet::new)));
			}
			return this;
		}

		/**
		 * Sets the scope(s).
		 *
		 * @param scopes the scope(s)
		 * @return the {@link Builder}
		 */
		public Builder scopes(Set<String> scopes) {
			this.scopes = scopes;
			return this;
		}

		/**
		 * Sets the state.
		 *
		 * @param state the state
		 * @return the {@link Builder}
		 */
		public Builder state(String state) {
			this.state = state;
			return this;
		}

		/**
		 * Sets the additional parameters used in the request.
		 *
		 * @param additionalParameters the additional parameters used in the request
		 * @return the {@link Builder}
		 */
		public Builder additionalParameters(Map<String, Object> additionalParameters) {
			this.additionalParameters = additionalParameters;
			return this;
		}

		/**
		 * Sets the {@code URI} string representation of the OAuth 2.0 Authorization Request.
		 *
		 * <p>
		 * <b>NOTE:</b> The {@code URI} string is <b>required</b> to be encoded in the
		 * {@code application/x-www-form-urlencoded} MIME format.
		 *
		 * @since 5.1
		 * @param authorizationRequestUri the {@code URI} string representation of the OAuth 2.0 Authorization Request
		 * @return the {@link Builder}
		 */
		public Builder authorizationRequestUri(String authorizationRequestUri) {
			this.authorizationRequestUri = authorizationRequestUri;
			return this;
		}

		/**
		 * Builds a new {@link OAuth2AuthorizationRequest}.
		 *
		 * @return a {@link OAuth2AuthorizationRequest}
		 */
		public OAuth2AuthorizationRequest build() {
			Assert.hasText(this.authorizationUri, "authorizationUri cannot be empty");
			Assert.hasText(this.clientId, "clientId cannot be empty");
			if (AuthorizationGrantType.IMPLICIT.equals(this.authorizationGrantType)) {
				Assert.hasText(this.redirectUri, "redirectUri cannot be empty");
			}

			OAuth2AuthorizationRequest authorizationRequest = new OAuth2AuthorizationRequest();
			authorizationRequest.authorizationUri = this.authorizationUri;
			authorizationRequest.authorizationGrantType = this.authorizationGrantType;
			authorizationRequest.responseType = this.responseType;
			authorizationRequest.clientId = this.clientId;
			authorizationRequest.redirectUri = this.redirectUri;
			authorizationRequest.state = this.state;
			authorizationRequest.scopes = Collections.unmodifiableSet(
				CollectionUtils.isEmpty(this.scopes) ?
					Collections.emptySet() : new LinkedHashSet<>(this.scopes));
			authorizationRequest.additionalParameters = Collections.unmodifiableMap(
				CollectionUtils.isEmpty(this.additionalParameters) ?
					Collections.emptyMap() : new LinkedHashMap<>(this.additionalParameters));
			authorizationRequest.authorizationRequestUri =
					StringUtils.hasText(this.authorizationRequestUri) ?
						this.authorizationRequestUri : this.buildAuthorizationRequestUri();

			return authorizationRequest;
		}

		private String buildAuthorizationRequestUri() {
			MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
			parameters.set(OAuth2ParameterNames.RESPONSE_TYPE, this.responseType.getValue());
			parameters.set(OAuth2ParameterNames.CLIENT_ID, this.clientId);
			if (!CollectionUtils.isEmpty(this.scopes)) {
				parameters.set(OAuth2ParameterNames.SCOPE,
						StringUtils.collectionToDelimitedString(this.scopes, " "));
			}
			if (this.state != null) {
				parameters.set(OAuth2ParameterNames.STATE, this.state);
			}
			if (this.redirectUri != null) {
				parameters.set(OAuth2ParameterNames.REDIRECT_URI, this.redirectUri);
			}
			if (!CollectionUtils.isEmpty(this.additionalParameters)) {
				this.additionalParameters.entrySet().stream()
						.filter(e -> !e.getKey().equals(OAuth2ParameterNames.REGISTRATION_ID))
						.forEach(e -> parameters.set(e.getKey(), e.getValue().toString()));
			}

			return UriComponentsBuilder.fromHttpUrl(this.authorizationUri)
					.queryParams(parameters)
					.encode(StandardCharsets.UTF_8)
					.build()
					.toUriString();
		}
	}
}
