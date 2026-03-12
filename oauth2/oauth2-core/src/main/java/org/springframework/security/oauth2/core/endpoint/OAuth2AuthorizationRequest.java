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

package org.springframework.security.oauth2.core.endpoint;

import java.io.Serial;
import java.io.Serializable;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Function;

import org.jspecify.annotations.Nullable;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.DefaultUriBuilderFactory;
import org.springframework.web.util.UriBuilder;
import org.springframework.web.util.UriUtils;

/**
 * A representation of an OAuth 2.0 Authorization Request for the authorization code grant
 * type.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AuthorizationGrantType
 * @see OAuth2AuthorizationResponseType
 * @see <a target="_blank" href=
 * "https://tools.ietf.org/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Code
 * Grant Request</a>
 */
public class OAuth2AuthorizationRequest implements Serializable {

	@Serial
	private static final long serialVersionUID = 620L;

	private final String authorizationUri;

	private final AuthorizationGrantType authorizationGrantType;

	private final OAuth2AuthorizationResponseType responseType;

	private final String clientId;

	private final @Nullable String redirectUri;

	private final Set<String> scopes;

	private final @Nullable String state;

	private final Map<String, Object> additionalParameters;

	private final String authorizationRequestUri;

	private final Map<String, Object> attributes;

	protected OAuth2AuthorizationRequest(AbstractBuilder<?, ?> builder) {
		Assert.notNull(builder.authorizationUri, "authorizationUri cannot be null");
		Assert.notNull(builder.clientId, "clientId cannot be null");
		Assert.hasText(builder.authorizationUri, "authorizationUri cannot be empty");
		Assert.hasText(builder.clientId, "clientId cannot be empty");
		this.authorizationUri = builder.authorizationUri;
		this.authorizationGrantType = builder.authorizationGrantType;
		this.responseType = builder.responseType;
		this.clientId = builder.clientId;
		this.redirectUri = builder.redirectUri;
		this.scopes = Collections.unmodifiableSet(
				CollectionUtils.isEmpty(builder.scopes) ? Collections.emptySet() : new LinkedHashSet<>(builder.scopes));
		this.state = builder.state;
		this.additionalParameters = Collections.unmodifiableMap(builder.additionalParameters);
		String builderAuthorizationRequestUri = builder.authorizationRequestUri;
		this.authorizationRequestUri = StringUtils.hasText(builderAuthorizationRequestUri)
				? builderAuthorizationRequestUri : builder.buildAuthorizationRequestUri();
		this.attributes = Collections.unmodifiableMap(builder.attributes);
	}

	/**
	 * Returns the uri for the authorization endpoint.
	 * @return the uri for the authorization endpoint
	 */
	public String getAuthorizationUri() {
		return this.authorizationUri;
	}

	/**
	 * Returns the {@link AuthorizationGrantType grant type}.
	 * @return the {@link AuthorizationGrantType}
	 */
	public AuthorizationGrantType getGrantType() {
		return this.authorizationGrantType;
	}

	/**
	 * Returns the {@link OAuth2AuthorizationResponseType response type}.
	 * @return the {@link OAuth2AuthorizationResponseType}
	 */
	public OAuth2AuthorizationResponseType getResponseType() {
		return this.responseType;
	}

	/**
	 * Returns the client identifier.
	 * @return the client identifier
	 */
	public String getClientId() {
		return this.clientId;
	}

	/**
	 * Returns the uri for the redirection endpoint, or {@code null} if not present.
	 * @return the uri for the redirection endpoint, or {@code null}
	 */
	public @Nullable String getRedirectUri() {
		return this.redirectUri;
	}

	/**
	 * Returns the scope(s).
	 * @return the scope(s), or an empty {@code Set} if not available
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}

	/**
	 * Returns the state, or {@code null} if not present.
	 * @return the state, or {@code null}
	 */
	public @Nullable String getState() {
		return this.state;
	}

	/**
	 * Returns the additional parameter(s) used in the request.
	 * @return a {@code Map} of the additional parameter(s), or an empty {@code Map} if
	 * not available
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

	/**
	 * Returns the attribute(s) associated to the request.
	 * @return a {@code Map} of the attribute(s), or an empty {@code Map} if not available
	 * @since 5.2
	 */
	public Map<String, Object> getAttributes() {
		return this.attributes;
	}

	/**
	 * Returns the value of an attribute associated to the request.
	 * @param <T> the type of the attribute
	 * @param name the name of the attribute
	 * @return the value of the attribute associated to the request, or {@code null} if
	 * not available
	 * @since 5.2
	 */
	@SuppressWarnings("unchecked")
	public <T> @Nullable T getAttribute(String name) {
		return (T) this.getAttributes().get(name);
	}

	/**
	 * Returns the {@code URI} string representation of the OAuth 2.0 Authorization
	 * Request.
	 *
	 * <p>
	 * <b>NOTE:</b> The {@code URI} string is encoded in the
	 * {@code application/x-www-form-urlencoded} MIME format.
	 * @return the {@code URI} string representation of the OAuth 2.0 Authorization
	 * Request
	 * @since 5.1
	 */
	public String getAuthorizationRequestUri() {
		return this.authorizationRequestUri;
	}

	/**
	 * Returns a new {@link Builder}, initialized with the authorization code grant type.
	 * @return the {@link Builder}
	 */
	public static Builder authorizationCode() {
		return new Builder();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}
		OAuth2AuthorizationRequest that = (OAuth2AuthorizationRequest) obj;

		return Objects.equals(this.authorizationUri, that.authorizationUri)
				&& Objects.equals(this.authorizationGrantType, that.authorizationGrantType)
				&& Objects.equals(this.responseType, that.responseType) && Objects.equals(this.clientId, that.clientId)
				&& Objects.equals(this.redirectUri, that.redirectUri) && Objects.equals(this.scopes, that.scopes)
				&& Objects.equals(this.state, that.state)
				&& Objects.equals(this.additionalParameters, that.additionalParameters)
				&& Objects.equals(this.authorizationRequestUri, that.authorizationRequestUri)
				&& Objects.equals(this.attributes, that.attributes);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.authorizationUri, this.clientId, this.authorizationGrantType, this.responseType,
				this.redirectUri, this.scopes, this.state, this.additionalParameters, this.authorizationRequestUri,
				this.attributes);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the values from the provided
	 * {@code authorizationRequest}.
	 * @param authorizationRequest the authorization request used for initializing the
	 * {@link Builder}
	 * @return the {@link Builder}
	 * @since 5.1
	 */
	public static Builder from(OAuth2AuthorizationRequest authorizationRequest) {
		Assert.notNull(authorizationRequest, "authorizationRequest cannot be null");
		// @formatter:off
		return new Builder()
				.authorizationUri(authorizationRequest.getAuthorizationUri())
				.clientId(authorizationRequest.getClientId())
				.redirectUri(authorizationRequest.getRedirectUri())
				.scopes(authorizationRequest.getScopes())
				.state(authorizationRequest.getState())
				.additionalParameters(authorizationRequest.getAdditionalParameters())
				.attributes(authorizationRequest.getAttributes());
		// @formatter:on
	}

	/**
	 * A builder for {@link OAuth2AuthorizationRequest}.
	 */
	public static class Builder extends AbstractBuilder<OAuth2AuthorizationRequest, Builder> {

		/**
		 * Builds a new {@link OAuth2AuthorizationRequest}.
		 * @return a {@link OAuth2AuthorizationRequest}
		 */
		@Override
		public OAuth2AuthorizationRequest build() {
			return new OAuth2AuthorizationRequest(this);
		}

	}

	/**
	 * A builder for subclasses of {@link OAuth2AuthorizationRequest}.
	 *
	 * @param <T> the type of authorization request
	 * @param <B> the type of the builder
	 */
	protected abstract static class AbstractBuilder<T extends OAuth2AuthorizationRequest, B extends AbstractBuilder<T, B>> {

		private @Nullable String authorizationUri;

		private final AuthorizationGrantType authorizationGrantType = AuthorizationGrantType.AUTHORIZATION_CODE;

		private final OAuth2AuthorizationResponseType responseType = OAuth2AuthorizationResponseType.CODE;

		private @Nullable String clientId;

		private @Nullable String redirectUri;

		private @Nullable Set<String> scopes;

		private @Nullable String state;

		private Map<String, Object> additionalParameters = new LinkedHashMap<>();

		private Consumer<Map<String, Object>> parametersConsumer = (params) -> {
		};

		private Map<String, Object> attributes = new LinkedHashMap<>();

		private @Nullable String authorizationRequestUri;

		private Function<UriBuilder, URI> authorizationRequestUriFunction = (builder) -> builder.build();

		private final DefaultUriBuilderFactory uriBuilderFactory;

		protected AbstractBuilder() {
			this.uriBuilderFactory = new DefaultUriBuilderFactory();
			// The supplied authorizationUri may contain encoded parameters
			// so disable encoding in UriBuilder and instead apply encoding within this
			// builder
			this.uriBuilderFactory.setEncodingMode(DefaultUriBuilderFactory.EncodingMode.NONE);
		}

		@SuppressWarnings("unchecked")
		protected final B getThis() {
			// avoid unchecked casts in subclasses by using "getThis()" instead of "(B)
			// this"
			return (B) this;
		}

		/**
		 * Sets the uri for the authorization endpoint.
		 * @param authorizationUri the uri for the authorization endpoint
		 * @return the {@link AbstractBuilder}
		 */
		public B authorizationUri(String authorizationUri) {
			this.authorizationUri = authorizationUri;
			return getThis();
		}

		/**
		 * Sets the client identifier.
		 * @param clientId the client identifier
		 * @return the {@link AbstractBuilder}
		 */
		public B clientId(String clientId) {
			this.clientId = clientId;
			return getThis();
		}

		/**
		 * Sets the uri for the redirection endpoint.
		 * @param redirectUri the uri for the redirection endpoint, may be {@code null}
		 * @return the {@link AbstractBuilder}
		 */
		public B redirectUri(@Nullable String redirectUri) {
			this.redirectUri = redirectUri;
			return getThis();
		}

		/**
		 * Sets the scope(s).
		 * @param scope the scope(s), may be {@code null}
		 * @return the {@link AbstractBuilder}
		 */
		public B scope(@Nullable String... scope) {
			if (scope != null && scope.length > 0) {
				return scopes(new LinkedHashSet<>(Arrays.asList(scope)));
			}
			return getThis();
		}

		/**
		 * Sets the scope(s).
		 * @param scopes the scope(s), may be {@code null}
		 * @return the {@link AbstractBuilder}
		 */
		public B scopes(@Nullable Set<String> scopes) {
			this.scopes = scopes;
			return getThis();
		}

		/**
		 * Sets the state.
		 * @param state the state, may be {@code null}
		 * @return the {@link AbstractBuilder}
		 */
		public B state(@Nullable String state) {
			this.state = state;
			return getThis();
		}

		/**
		 * Sets the additional parameter(s) used in the request.
		 * @param additionalParameters the additional parameter(s) used in the request
		 * @return the {@link AbstractBuilder}
		 */
		public B additionalParameters(Map<String, Object> additionalParameters) {
			if (!CollectionUtils.isEmpty(additionalParameters)) {
				this.additionalParameters.putAll(additionalParameters);
			}
			return getThis();
		}

		/**
		 * A {@code Consumer} to be provided access to the additional parameter(s)
		 * allowing the ability to add, replace, or remove.
		 * @param additionalParametersConsumer a {@code Consumer} of the additional
		 * parameters
		 * @return the {@link AbstractBuilder}
		 * @since 5.3
		 */
		public B additionalParameters(Consumer<Map<String, Object>> additionalParametersConsumer) {
			if (additionalParametersConsumer != null) {
				additionalParametersConsumer.accept(this.additionalParameters);
			}
			return getThis();
		}

		/**
		 * A {@code Consumer} to be provided access to all the parameters allowing the
		 * ability to add, replace, or remove.
		 * @param parametersConsumer a {@code Consumer} of all the parameters
		 * @return the {@link AbstractBuilder}
		 * @since 5.3
		 */
		public B parameters(Consumer<Map<String, Object>> parametersConsumer) {
			if (parametersConsumer != null) {
				this.parametersConsumer = parametersConsumer;
			}
			return getThis();
		}

		/**
		 * Sets the attributes associated to the request.
		 * @param attributes the attributes associated to the request
		 * @return the {@link AbstractBuilder}
		 * @since 5.2
		 */
		public B attributes(Map<String, Object> attributes) {
			if (!CollectionUtils.isEmpty(attributes)) {
				this.attributes.putAll(attributes);
			}
			return getThis();
		}

		/**
		 * A {@code Consumer} to be provided access to the attribute(s) allowing the
		 * ability to add, replace, or remove.
		 * @param attributesConsumer a {@code Consumer} of the attribute(s)
		 * @return the {@link AbstractBuilder}
		 * @since 5.3
		 */
		public B attributes(Consumer<Map<String, Object>> attributesConsumer) {
			if (attributesConsumer != null) {
				attributesConsumer.accept(this.attributes);
			}
			return getThis();
		}

		/**
		 * Sets the {@code URI} string representation of the OAuth 2.0 Authorization
		 * Request.
		 *
		 * <p>
		 * <b>NOTE:</b> The {@code URI} string is <b>required</b> to be encoded in the
		 * {@code application/x-www-form-urlencoded} MIME format.
		 * @param authorizationRequestUri the {@code URI} string representation of the
		 * OAuth 2.0 Authorization Request
		 * @return the {@link AbstractBuilder}
		 * @since 5.1
		 */
		public B authorizationRequestUri(String authorizationRequestUri) {
			this.authorizationRequestUri = authorizationRequestUri;
			return getThis();
		}

		/**
		 * A {@code Function} to be provided a {@code UriBuilder} representation of the
		 * OAuth 2.0 Authorization Request allowing for further customizations.
		 * @param authorizationRequestUriFunction a {@code Function} to be provided a
		 * {@code UriBuilder} representation of the OAuth 2.0 Authorization Request
		 * @return the {@link AbstractBuilder}
		 * @since 5.3
		 */
		public B authorizationRequestUri(Function<UriBuilder, URI> authorizationRequestUriFunction) {
			if (authorizationRequestUriFunction != null) {
				this.authorizationRequestUriFunction = authorizationRequestUriFunction;
			}
			return getThis();
		}

		public abstract T build();

		private String buildAuthorizationRequestUri() {
			Map<String, Object> parameters = getParameters(); // Not encoded
			this.parametersConsumer.accept(parameters);
			MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
			parameters.forEach((k, v) -> {
				String key = encodeQueryParam(k);
				if (v instanceof Iterable) {
					((Iterable<?>) v).forEach((value) -> queryParams.add(key, encodeQueryParam(String.valueOf(value))));
				}
				else if (v != null && v.getClass().isArray()) {
					Object[] values = (Object[]) v;
					for (Object value : values) {
						queryParams.add(key, encodeQueryParam(String.valueOf(value)));
					}
				}
				else {
					queryParams.set(key, encodeQueryParam(String.valueOf(v)));
				}
			});
			Assert.notNull(this.authorizationUri, "authorizationUri cannot be null");
			UriBuilder uriBuilder = this.uriBuilderFactory.uriString(this.authorizationUri).queryParams(queryParams);
			return this.authorizationRequestUriFunction.apply(uriBuilder).toString();
		}

		protected Map<String, Object> getParameters() {
			Map<String, Object> parameters = new LinkedHashMap<>();
			parameters.put(OAuth2ParameterNames.RESPONSE_TYPE, this.responseType.getValue());
			parameters.put(OAuth2ParameterNames.CLIENT_ID, this.clientId);
			if (!CollectionUtils.isEmpty(this.scopes)) {
				parameters.put(OAuth2ParameterNames.SCOPE, StringUtils.collectionToDelimitedString(this.scopes, " "));
			}
			if (this.state != null) {
				parameters.put(OAuth2ParameterNames.STATE, this.state);
			}
			if (this.redirectUri != null) {
				parameters.put(OAuth2ParameterNames.REDIRECT_URI, this.redirectUri);
			}
			parameters.putAll(this.additionalParameters);
			return parameters;
		}

		// Encode query parameter value according to RFC 3986
		private static String encodeQueryParam(String value) {
			return UriUtils.encodeQueryParam(value, StandardCharsets.UTF_8);
		}

	}

}
