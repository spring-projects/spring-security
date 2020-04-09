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
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collection;
import java.util.Map;

/**
 * An implementation of an {@link org.springframework.security.authentication.AuthenticationProvider} for OAuth 2.0 Login,
 * which leverages the OAuth 2.0 Authorization Code Grant Flow.
 * <p>
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
 * @author Mark Heckler
 * @since 5.1
 * @see OAuth2LoginAuthenticationToken
 * @see ReactiveOAuth2AccessTokenResponseClient
 * @see ReactiveOAuth2UserService
 * @see OAuth2User
 * @see ReactiveOidcIdTokenDecoderFactory
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1">Section 4.1 Authorization Code Grant Flow</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.3">Section 4.1.3 Access Token Request</a>
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc6749#section-4.1.4">Section 4.1.4 Access Token Response</a>
 */
public class OidcAuthorizationCodeReactiveAuthenticationManager implements
		ReactiveAuthenticationManager {

	private static final String INVALID_STATE_PARAMETER_ERROR_CODE = "invalid_state_parameter";
	private static final String INVALID_ID_TOKEN_ERROR_CODE = "invalid_id_token";
	private static final String INVALID_NONCE_ERROR_CODE = "invalid_nonce";

	private final ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

	private final ReactiveOAuth2UserService<OidcUserRequest, OidcUser> userService;

	private GrantedAuthoritiesMapper authoritiesMapper = (authorities -> authorities);

	private ReactiveJwtDecoderFactory<ClientRegistration> jwtDecoderFactory = new ReactiveOidcIdTokenDecoderFactory();

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
				throw new OAuth2AuthenticationException(
						authorizationResponse.getError(), authorizationResponse.getError().toString());
			}

			if (!authorizationResponse.getState().equals(authorizationRequest.getState())) {
				OAuth2Error oauth2Error = new OAuth2Error(INVALID_STATE_PARAMETER_ERROR_CODE);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}

			OAuth2AuthorizationCodeGrantRequest authzRequest = new OAuth2AuthorizationCodeGrantRequest(
					authorizationCodeAuthentication.getClientRegistration(),
					authorizationCodeAuthentication.getAuthorizationExchange());

			return this.accessTokenResponseClient.getTokenResponse(authzRequest)
					.flatMap(accessTokenResponse -> authenticationResult(authorizationCodeAuthentication, accessTokenResponse))
					.onErrorMap(OAuth2AuthorizationException.class, e -> new OAuth2AuthenticationException(e.getError(), e.getError().toString()))
					.onErrorMap(JwtException.class, e -> {
						OAuth2Error invalidIdTokenError = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE, e.getMessage(), null);
						throw new OAuth2AuthenticationException(invalidIdTokenError, invalidIdTokenError.toString(), e);
					});
		});
	}

	/**
	 * Sets the {@link ReactiveJwtDecoderFactory} used for {@link OidcIdToken} signature verification.
	 * The factory returns a {@link ReactiveJwtDecoder} associated to the provided {@link ClientRegistration}.
	 *
	 * @since 5.2
	 * @param jwtDecoderFactory the {@link ReactiveJwtDecoderFactory} used for {@link OidcIdToken} signature verification
	 */
	public final void setJwtDecoderFactory(ReactiveJwtDecoderFactory<ClientRegistration> jwtDecoderFactory) {
		Assert.notNull(jwtDecoderFactory, "jwtDecoderFactory cannot be null");
		this.jwtDecoderFactory = jwtDecoderFactory;
	}

	/**
	 * Sets the {@link GrantedAuthoritiesMapper} used for mapping {@link OidcUser#getAuthorities()}
	 * to a new set of authorities which will be associated to the {@link OAuth2LoginAuthenticationToken}.
	 *
	 * @since 5.4
	 * @param authoritiesMapper the {@link GrantedAuthoritiesMapper} used for mapping the user's authorities
	 */
	public final void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		Assert.notNull(authoritiesMapper, "authoritiesMapper cannot be null");
		this.authoritiesMapper = authoritiesMapper;
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
			throw new OAuth2AuthenticationException(invalidIdTokenError, invalidIdTokenError.toString());
		}

		return createOidcToken(clientRegistration, accessTokenResponse)
				.doOnNext(idToken -> validateNonce(authorizationCodeAuthentication, idToken))
				.map(idToken -> new OidcUserRequest(clientRegistration, accessToken, idToken, additionalParameters))
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
		ReactiveJwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(clientRegistration);
		String rawIdToken = (String) accessTokenResponse.getAdditionalParameters().get(OidcParameterNames.ID_TOKEN);
		return jwtDecoder.decode(rawIdToken)
				.map(jwt -> new OidcIdToken(jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaims()));
	}

	private static Mono<OidcIdToken> validateNonce(OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication, OidcIdToken idToken) {
		String requestNonce = authorizationCodeAuthentication.getAuthorizationExchange()
				.getAuthorizationRequest().getAttribute(OidcParameterNames.NONCE);
		if (requestNonce != null) {
			String nonceHash;
			try {
				nonceHash = createHash(requestNonce);
			} catch (NoSuchAlgorithmException e) {
				OAuth2Error oauth2Error = new OAuth2Error(INVALID_NONCE_ERROR_CODE);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
			String nonceHashClaim = idToken.getNonce();
			if (nonceHashClaim == null || !nonceHashClaim.equals(nonceHash)) {
				OAuth2Error oauth2Error = new OAuth2Error(INVALID_NONCE_ERROR_CODE);
				throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
			}
		}

		return Mono.just(idToken);
	}

	static String createHash(String nonce) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(nonce.getBytes(StandardCharsets.US_ASCII));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}
}
