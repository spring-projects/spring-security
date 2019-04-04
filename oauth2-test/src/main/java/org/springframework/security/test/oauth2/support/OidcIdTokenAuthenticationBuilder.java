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
package org.springframework.security.test.oauth2.support;

import static org.springframework.security.test.oauth2.support.CollectionsSupport.putIfNotEmpty;

import java.time.Instant;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.util.StringUtils;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class OidcIdTokenAuthenticationBuilder<T extends OidcIdTokenAuthenticationBuilder<T>>
		extends
		AbstractAuthenticationBuilder<T> {
	public static final String DEFAULT_TOKEN_VALUE = "Open ID test";
	public static final String DEFAULT_NAME_KEY = "sub";
	public static final String REQUEST_REDIRECT_URI = "https://localhost:8080/";
	public static final String REQUEST_AUTHORIZATION_URI = "https://localhost:8080/authorize";
	public static final String REQUEST_GRANT_TYPE = "authorization_code";
	public static final String CLIENT_TOKEN_URI = "https://localhost:8080/token";
	public static final String CLIENT_ID = "mocked-client";
	public static final String CLIENT_REGISTRATION_ID = "mocked-registration";
	public static final String CLIENT_GRANT_TYPE = "client_credentials";

	protected String tokenValue = DEFAULT_TOKEN_VALUE;
	protected String nameAttributeKey = DEFAULT_NAME_KEY;
	protected final ClientRegistration.Builder clientRegistrationBuilder;
	protected final OAuth2AuthorizationRequest.Builder authorizationRequestBuilder;

	public OidcIdTokenAuthenticationBuilder(
			final ClientRegistration.Builder clientRegistration,
			final OAuth2AuthorizationRequest.Builder authorizationRequest) {
		super();
		this.clientRegistrationBuilder = clientRegistration;
		this.authorizationRequestBuilder = authorizationRequest;
		this.authorizationRequestBuilder.attributes(claims);
	}

	public OidcIdTokenAuthenticationBuilder(final AuthorizationGrantType requestAuthorizationGrantType) {
		this(defaultClientRegistration(), defaultAuthorizationRequest(requestAuthorizationGrantType));
	}

	public T tokenValue(final String tokenValue) {
		this.tokenValue = tokenValue;
		return downCast();
	}

	public T nameAttributeKey(final String nameAttributeKey) {
		this.nameAttributeKey = nameAttributeKey;
		return downCast();
	}

	public static ClientRegistration.Builder defaultClientRegistration() {
		return ClientRegistration.withRegistrationId(CLIENT_REGISTRATION_ID)
				.authorizationGrantType(new AuthorizationGrantType(CLIENT_GRANT_TYPE))
				.clientId(CLIENT_ID)
				.tokenUri(CLIENT_TOKEN_URI);
	}

	public static OAuth2AuthorizationRequest.Builder
			defaultAuthorizationRequest(final AuthorizationGrantType authorizationGrantType) {
		return authorizationRequestBuilder(authorizationGrantType).authorizationUri(REQUEST_AUTHORIZATION_URI)
				.clientId(CLIENT_ID)
				.redirectUri(REQUEST_REDIRECT_URI);
	}

	public static OAuth2AuthorizationRequest.Builder
			authorizationRequestBuilder(final AuthorizationGrantType authorizationGrantType) {
		if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)) {
			return OAuth2AuthorizationRequest.authorizationCode();
		}
		if (AuthorizationGrantType.IMPLICIT.equals(authorizationGrantType)) {
			return OAuth2AuthorizationRequest.implicit();
		}
		throw new UnsupportedOperationException(
				"Only authorization_code and implicit grant types are supported for MockOAuth2AuthorizationRequest");
	}

	public OAuth2LoginAuthenticationToken build() {
		assert (!StringUtils.isEmpty(nameAttributeKey));
		assert (!claims.containsKey(nameAttributeKey) || claims.get(nameAttributeKey).equals(name));

		putIfNotEmpty(nameAttributeKey, name, claims);

		final Set<String> scopes = getAllScopes();
		putIfNotEmpty(scopeClaimName, scopes, claims);

		final OidcIdToken token = new OidcIdToken(
				tokenValue,
				(Instant) claims.get(IdTokenClaimNames.IAT),
				(Instant) claims.get(IdTokenClaimNames.EXP),
				claims);

		final ClientRegistration clientRegistration =
				clientRegistrationBuilder.scope(scopes).userNameAttributeName(nameAttributeKey).build();

		final OAuth2AuthorizationRequest authorizationRequest =
				authorizationRequestBuilder.attributes(claims).scopes(scopes).build();

		final String redirectUri =
				StringUtils.isEmpty(authorizationRequest.getRedirectUri()) ? clientRegistration.getRedirectUriTemplate()
						: authorizationRequest.getRedirectUri();

		final OAuth2AuthorizationExchange authorizationExchange =
				new OAuth2AuthorizationExchange(authorizationRequest, auth2AuthorizationResponse(redirectUri));

		final Collection<? extends GrantedAuthority> authorities = getAllAuthorities();
		final DefaultOidcUser principal = new DefaultOidcUser(authorities, token, nameAttributeKey);

		final OAuth2AccessToken accessToken = new OAuth2AccessToken(
				TokenType.BEARER,
				tokenValue,
				(Instant) claims.get(IdTokenClaimNames.IAT),
				(Instant) claims.get(IdTokenClaimNames.EXP),
				authorizationExchange.getAuthorizationRequest().getScopes());

		return new OAuth2LoginAuthenticationToken(
				clientRegistration,
				authorizationExchange,
				principal,
				authorities,
				accessToken);
	}

	private static OAuth2AuthorizationResponse auth2AuthorizationResponse(final String redirectUri) {
		final OAuth2AuthorizationResponse.Builder builder =
				OAuth2AuthorizationResponse.success("test-authorization-success-code");
		builder.redirectUri(redirectUri);
		return builder.build();
	}

	public static class ClientRegistrationBuilder<T extends ClientRegistrationBuilder<T>> {
		private final ClientRegistration.Builder delegate;

		public ClientRegistrationBuilder(final ClientRegistration.Builder delegate) {
			this.delegate = delegate;
		}

		public T authorizationGrantType(final AuthorizationGrantType authorizationGrantType) {
			delegate.authorizationGrantType(authorizationGrantType);
			return downcast();
		}

		public T authorizationUri(final String authorizationUri) {
			delegate.authorizationUri(authorizationUri);
			return downcast();
		}

		public T clientAuthenticationMethod(final ClientAuthenticationMethod clientAuthenticationMethod) {
			delegate.clientAuthenticationMethod(clientAuthenticationMethod);
			return downcast();
		}

		public T clientId(final String clientId) {
			delegate.clientId(clientId);
			return downcast();
		}

		public T clientName(final String clientName) {
			delegate.clientName(clientName);
			return downcast();
		}

		public T clientSecret(final String clientSecret) {
			delegate.clientSecret(clientSecret);
			return downcast();
		}

		public T jwkSetUri(final String jwkSetUri) {
			delegate.jwkSetUri(jwkSetUri);
			return downcast();
		}

		public T providerConfigurationMetadata(final Map<String, Object> configurationMetadata) {
			delegate.providerConfigurationMetadata(configurationMetadata);
			return downcast();
		}

		public T redirectUriTemplate(final String redirectUriTemplate) {
			delegate.redirectUriTemplate(redirectUriTemplate);
			return downcast();
		}

		public T registrationId(final String registrationId) {
			delegate.registrationId(registrationId);
			return downcast();
		}

		public T tokenUri(final String tokenUri) {
			delegate.tokenUri(tokenUri);
			return downcast();
		}

		public T userInfoAuthenticationMethod(final AuthenticationMethod userInfoAuthenticationMethod) {
			delegate.userInfoAuthenticationMethod(userInfoAuthenticationMethod);
			return downcast();
		}

		@SuppressWarnings("unchecked")
		protected T downcast() {
			return (T) this;
		}
	}

	public static class AuthorizationRequestBuilder<T extends AuthorizationRequestBuilder<T>> {
		private final OAuth2AuthorizationRequest.Builder delegate;
		private final Map<String, Object> additionalParameters;

		public AuthorizationRequestBuilder(
				final OAuth2AuthorizationRequest.Builder builder,
				final Map<String, Object> additionalParameters) {
			this.additionalParameters = additionalParameters;
			this.delegate = builder;
			this.delegate.additionalParameters(additionalParameters);
		}

		public T additionalParameter(final String name, final Object value) {
			additionalParameters.put(name, value);
			return downcast();
		}

		public T authorizationRequestUri(final String authorizationRequestUri) {
			delegate.authorizationRequestUri(authorizationRequestUri);
			return downcast();
		}

		public T authorizationUri(final String authorizationUri) {
			delegate.authorizationUri(authorizationUri);
			return downcast();
		}

		public T clientId(final String clientId) {
			delegate.clientId(clientId);
			return downcast();
		}

		public T redirectUri(final String redirectUri) {
			delegate.redirectUri(redirectUri);
			return downcast();
		}

		public T state(final String state) {
			delegate.state(state);
			return downcast();
		}

		@SuppressWarnings("unchecked")
		protected T downcast() {
			return (T) this;
		}
	}

}
