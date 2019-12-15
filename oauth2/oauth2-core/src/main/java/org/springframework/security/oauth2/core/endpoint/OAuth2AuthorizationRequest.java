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
package org.springframework.security.oauth2.core.endpoint;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriBuilder;
import org.springframework.web.util.UriUtils;

import java.io.Serializable;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;

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
	private Map<String, Object> attributes;

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
	 * @return the scope(s), or an empty {@code Set} if not available
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
	 * Returns the additional parameter(s) used in the request.
	 *
	 * @return a {@code Map} of the additional parameter(s), or an empty {@code Map} if not available
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

	/**
	 * Returns the attribute(s) associated to the request.
	 *
	 * @since 5.2
	 * @return a {@code Map} of the attribute(s), or an empty {@code Map} if not available
	 */
	public Map<String, Object> getAttributes() {
		return this.attributes;
	}

	/**
	 * Returns the value of an attribute associated to the request.
	 *
	 * @since 5.2
	 * @param name the name of the attribute
	 * @param <T> the type of the attribute
	 * @return the value of the attribute associated to the request, or {@code null} if not available
	 */
	@SuppressWarnings("unchecked")
	public <T> T getAttribute(String name) {
		return (T) this.getAttributes().get(name);
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
				.additionalParameters(authorizationRequest.getAdditionalParameters())
				.attributes(authorizationRequest.getAttributes());
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
		private Consumer<Map<String, Object>> additionalParametersConsumer = params -> {};
		private Consumer<Map<String, Object>> parametersConsumer = params -> {};
		private Consumer<Map<String, Object>> attributesConsumer = attrs -> {};
		private String authorizationRequestUri;
		private Function<UriBuilder, URI> authorizationRequestUriFunction = builder -> builder.build();
		private final DefaultUriBuilderFactory uriBuilderFactory;

		private Builder(AuthorizationGrantType authorizationGrantType) {
			Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
			this.authorizationGrantType = authorizationGrantType;
			if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)) {
				this.responseType = OAuth2AuthorizationResponseType.CODE;
			} else if (AuthorizationGrantType.IMPLICIT.equals(authorizationGrantType)) {
				this.responseType = OAuth2AuthorizationResponseType.TOKEN;
			}
			this.uriBuilderFactory = new DefaultUriBuilderFactory();
			// The supplied authorizationUri may contain encoded parameters
			// so disable encoding in UriBuilder and instead apply encoding within this builder
			this.uriBuilderFactory.setEncodingMode(DefaultUriBuilderFactory.EncodingMode.NONE);
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
				return scopes(new LinkedHashSet<>(Arrays.asList(scope)));
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
		 * Sets the additional parameter(s) used in the request.
		 *
		 * @param additionalParameters the additional parameter(s) used in the request
		 * @return the {@link Builder}
		 */
		public Builder additionalParameters(Map<String, Object> additionalParameters) {
			if (additionalParameters != null) {
				return additionalParameters(params -> params.putAll(additionalParameters));
			}
			return this;
		}

		/**
		 * A {@code Consumer} to be provided access to the additional parameter(s)
		 * allowing the ability to add, replace, or remove.
		 *
		 * @since 5.3
		 * @param additionalParametersConsumer a {@code Consumer} of the additional parameters
		 */
		public Builder additionalParameters(Consumer<Map<String, Object>> additionalParametersConsumer) {
			if (additionalParametersConsumer != null) {
				this.additionalParametersConsumer = additionalParametersConsumer;
			}
			return this;
		}

		/**
		 * A {@code Consumer} to be provided access to all the parameters
		 * allowing the ability to add, replace, or remove.
		 *
		 * @since 5.3
		 * @param parametersConsumer a {@code Consumer} of all the parameters
		 */
		public Builder parameters(Consumer<Map<String, Object>> parametersConsumer) {
			if (parametersConsumer != null) {
				this.parametersConsumer = parametersConsumer;
			}
			return this;
		}

		/**
		 * Sets the attributes associated to the request.
		 *
		 * @since 5.2
		 * @param attributes the attributes associated to the request
		 * @return the {@link Builder}
		 */
		public Builder attributes(Map<String, Object> attributes) {
			if (attributes != null) {
				return attributes(attrs -> attrs.putAll(attributes));
			}
			return this;
		}

		/**
		 * A {@code Consumer} to be provided access to the attribute(s)
		 * allowing the ability to add, replace, or remove.
		 *
		 * @since 5.3
		 * @param attributesConsumer a {@code Consumer} of the attribute(s)
		 */
		public Builder attributes(Consumer<Map<String, Object>> attributesConsumer) {
			if (attributesConsumer != null) {
				this.attributesConsumer = attributesConsumer;
			}
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
		 * A {@code Function} to be provided a {@code UriBuilder} representation
		 * of the OAuth 2.0 Authorization Request allowing for further customizations.
		 *
		 * @since 5.3
		 * @param authorizationRequestUriFunction a {@code Function} to be provided a {@code UriBuilder} representation of the OAuth 2.0 Authorization Request
		 */
		public Builder authorizationRequestUri(Function<UriBuilder, URI> authorizationRequestUriFunction) {
			if (authorizationRequestUriFunction != null) {
				this.authorizationRequestUriFunction = authorizationRequestUriFunction;
			}
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
			Map<String, Object> additionalParameters = new LinkedHashMap<>();
			this.additionalParametersConsumer.accept(additionalParameters);
			authorizationRequest.additionalParameters = Collections.unmodifiableMap(additionalParameters);
			Map<String, Object> attributes = new LinkedHashMap<>();
			this.attributesConsumer.accept(attributes);
			authorizationRequest.attributes = Collections.unmodifiableMap(attributes);
			authorizationRequest.authorizationRequestUri =
					StringUtils.hasText(this.authorizationRequestUri) ?
							this.authorizationRequestUri : this.buildAuthorizationRequestUri();

			return authorizationRequest;
		}

		private String buildAuthorizationRequestUri() {
			Map<String, Object> parameters = getParameters();	// Not encoded
			this.parametersConsumer.accept(parameters);
			MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
			parameters.forEach((k, v) -> queryParams.set(
					encodeQueryParam(k), encodeQueryParam(v.toString())));		// Encoded
			UriBuilder uriBuilder = this.uriBuilderFactory.uriString(this.authorizationUri)
					.queryParams(queryParams);
			return this.authorizationRequestUriFunction.apply(uriBuilder).toString();
		}

		private Map<String, Object> getParameters() {
			Map<String, Object> parameters = new LinkedHashMap<>();
			parameters.put(OAuth2ParameterNames.RESPONSE_TYPE, this.responseType.getValue());
			parameters.put(OAuth2ParameterNames.CLIENT_ID, this.clientId);
			if (!CollectionUtils.isEmpty(this.scopes)) {
				parameters.put(OAuth2ParameterNames.SCOPE,
						StringUtils.collectionToDelimitedString(this.scopes, " "));
			}
			if (this.state != null) {
				parameters.put(OAuth2ParameterNames.STATE, this.state);
			}
			if (this.redirectUri != null) {
				parameters.put(OAuth2ParameterNames.REDIRECT_URI, this.redirectUri);
			}
			Map<String, Object> additionalParameters = new LinkedHashMap<>();
			this.additionalParametersConsumer.accept(additionalParameters);
			additionalParameters.forEach((k, v) -> parameters.put(k, v.toString()));
			return parameters;
		}

		// Encode query parameter value according to RFC 3986
		private static String encodeQueryParam(String value) {
			return UriUtils.encodeQueryParam(value, StandardCharsets.UTF_8);
		}
	}
}
