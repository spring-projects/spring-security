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
package org.springframework.security.oauth2.client.oidc.authentication;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/**
 * An implementation of an {@link org.springframework.security.authentication.AuthenticationProvider} for OAuth 2.0 Login,
 * which leverages the OAuth 2.0 Authorization Code Grant Flow.
 *
 * This {@link org.springframework.security.authentication.AuthenticationProvider} is responsible for authenticating
 * an Authorization Code credential with the Authorization Server's Token Endpoint
 * and if valid, exchanging it for an Access Token credential.
 * <p>
 * It will also obtain the user attributes of the End-User (Resource Owner)
 * from the UserInfo Endpoint using an {@link org.springframework.security.oauth2.client.userinfo.OAuth2UserService},
 * which will create a {@code Principal} in the form of an {@link OAuth2User}.
 * The {@code OAuth2User} is then associated to the {@link OAuth2LoginAuthenticationToken}
 * to complete the authentication.
 *
 * @author Rob Winch
 * @since 5.1
 * @see OAuth2LoginAuthenticationToken
 * @see ReactiveOAuth2AccessTokenResponseClient
 * @see ReactiveOAuth2UserService
 * @see OAuth2User
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant Flow</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.4">Section 4.1.4 Access Token Response</a>
 */
public class OidcAuthorizationCodeReactiveAuthenticationManager implements
		ReactiveAuthenticationManager {

	private static final String INVALID_STATE_PARAMETER_ERROR_CODE = "invalid_state_parameter";
	private static final String INVALID_ID_TOKEN_ERROR_CODE = "invalid_id_token";
	private static final String MISSING_SIGNATURE_VERIFIER_ERROR_CODE = "missing_signature_verifier";

	private final ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

	private final ReactiveOAuth2UserService<OidcUserRequest, OidcUser> userService;

	private GrantedAuthoritiesMapper authoritiesMapper = (authorities -> authorities);

	private Function<ClientRegistration, ReactiveJwtDecoder> decoderFactory = new DefaultDecoderFactory();

	public OidcAuthorizationCodeReactiveAuthenticationManager(
			ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient,
			ReactiveOAuth2UserService<OidcUserRequest, OidcUser> userService) {
		Assert.notNull(accessTokenResponseClient, "accessTokenResponseClient cannot be null");
		Assert.notNull(userService, "userService cannot be null");
		this.accessTokenResponseClient = accessTokenResponseClient;
		this.userService = userService;
	}

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		return Mono.defer(() -> {
			OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication = (OAuth2AuthorizationCodeAuthenticationToken) authentication;

			// Section 3.1.2.1 Authentication Request - https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
			// scope REQUIRED. OpenID Connect requests MUST contain the "openid" scope value.
			if (!authorizationCodeAuthentication.getAuthorizationExchange()
					.getAuthorizationRequest().getScopes().contains("openid")) {
				// This is an OpenID Connect Authentication Request so return empty
				// and let OAuth2LoginReactiveAuthenticationManager handle it instead
				return Mono.empty();
			}


			OAuth2AuthorizationRequest authorizationRequest = authorizationCodeAuthentication
					.getAuthorizationExchange().getAuthorizationRequest();
			OAuth2AuthorizationResponse authorizationResponse = authorizationCodeAuthentication
					.getAuthorizationExchange().getAuthorizationResponse();

			if (authorizationResponse.statusError()) {
				return Mono.error(new OAuth2AuthenticationException(
						authorizationResponse.getError(), authorizationResponse.getError().toString()));
			}

			if (!authorizationResponse.getState().equals(authorizationRequest.getState())) {
				OAuth2Error oauth2Error = new OAuth2Error(INVALID_STATE_PARAMETER_ERROR_CODE);
				return Mono.error(new OAuth2AuthenticationException(
						oauth2Error, oauth2Error.toString()));
			}

			OAuth2AuthorizationCodeGrantRequest authzRequest = new OAuth2AuthorizationCodeGrantRequest(
					authorizationCodeAuthentication.getClientRegistration(),
					authorizationCodeAuthentication.getAuthorizationExchange());

			return this.accessTokenResponseClient.getTokenResponse(authzRequest)
					.flatMap(accessTokenResponse -> authenticationResult(authorizationCodeAuthentication, accessTokenResponse))
					.onErrorMap(OAuth2AuthorizationException.class, e -> new OAuth2AuthenticationException(e.getError(), e.getError().toString()));
		});
	}

	/**
	 * Provides a way to customize the {@link ReactiveJwtDecoder} given a {@link ClientRegistration}
	 * @param decoderFactory the {@link Function} used to create {@link ReactiveJwtDecoder} instance. Cannot be null.
	 */
	void setDecoderFactory(
			Function<ClientRegistration, ReactiveJwtDecoder> decoderFactory) {
		Assert.notNull(decoderFactory, "decoderFactory cannot be null");
		this.decoderFactory = decoderFactory;
	}

	private Mono<OAuth2LoginAuthenticationToken> authenticationResult(OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication, OAuth2AccessTokenResponse accessTokenResponse) {
		OAuth2AccessToken accessToken = accessTokenResponse.getAccessToken();
		ClientRegistration clientRegistration = authorizationCodeAuthentication.getClientRegistration();
		Map<String, Object> additionalParameters = accessTokenResponse.getAdditionalParameters();

		if (!additionalParameters.containsKey(OidcParameterNames.ID_TOKEN)) {
			OAuth2Error invalidIdTokenError = new OAuth2Error(
					INVALID_ID_TOKEN_ERROR_CODE,
					"Missing (required) ID Token in Token Response for Client Registration: " + clientRegistration.getRegistrationId(),
					null);
			return Mono.error(new OAuth2AuthenticationException(invalidIdTokenError, invalidIdTokenError.toString()));
		}

		return createOidcToken(clientRegistration, accessTokenResponse)
				.map(idToken ->  new OidcUserRequest(clientRegistration, accessToken, idToken, additionalParameters))
				.flatMap(this.userService::loadUser)
				.map(oauth2User -> {
					Collection<? extends GrantedAuthority> mappedAuthorities =
							this.authoritiesMapper.mapAuthorities(oauth2User.getAuthorities());

					return new OAuth2LoginAuthenticationToken(
							authorizationCodeAuthentication.getClientRegistration(),
							authorizationCodeAuthentication.getAuthorizationExchange(),
							oauth2User,
							mappedAuthorities,
							accessToken,
							accessTokenResponse.getRefreshToken());
				});
	}

	private Mono<OidcIdToken> createOidcToken(ClientRegistration clientRegistration, OAuth2AccessTokenResponse accessTokenResponse) {
		ReactiveJwtDecoder jwtDecoder = this.decoderFactory.apply(clientRegistration);
		String rawIdToken = (String) accessTokenResponse.getAdditionalParameters().get(OidcParameterNames.ID_TOKEN);
		return jwtDecoder.decode(rawIdToken)
				.map(jwt -> new OidcIdToken(jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaims()))
				.doOnNext(idToken -> OidcTokenValidator.validateIdToken(idToken, clientRegistration));
	}

	private static class DefaultDecoderFactory implements Function<ClientRegistration, ReactiveJwtDecoder> {
		private final Map<String, ReactiveJwtDecoder> jwtDecoders = new ConcurrentHashMap<>();

		@Override
		public ReactiveJwtDecoder apply(ClientRegistration clientRegistration) {
			ReactiveJwtDecoder jwtDecoder = this.jwtDecoders.get(clientRegistration.getRegistrationId());
			if (jwtDecoder == null) {
				if (!StringUtils.hasText(clientRegistration.getProviderDetails().getJwkSetUri())) {
					OAuth2Error oauth2Error = new OAuth2Error(
							MISSING_SIGNATURE_VERIFIER_ERROR_CODE,
							"Failed to find a Signature Verifier for Client Registration: '" +
									clientRegistration.getRegistrationId() + "'. Check to ensure you have configured the JwkSet URI.",
							null
					);
					throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
				}
				jwtDecoder = new NimbusReactiveJwtDecoder(clientRegistration.getProviderDetails().getJwkSetUri());
				this.jwtDecoders.put(clientRegistration.getRegistrationId(), jwtDecoder);
			}
			return jwtDecoder;
		}
	}
}
