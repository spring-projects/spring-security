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

package org.springframework.security.oauth2.client;

import java.time.Duration;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.authentication.ReactiveOidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;

/**
 * A {@link ReactiveOAuth2AuthorizationSuccessHandler} that refreshes an {@link OidcUser}
 * in the {@link SecurityContext} if the refreshed {@link OidcIdToken} is valid according
 * to <a href=
 * "https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse">OpenID
 * Connect Core 1.0 - Section 12.2 Successful Refresh Response</a>
 *
 * @author Evgeniy Cheban
 * @since 7.1
 * @see RefreshTokenReactiveOAuth2AuthorizedClientProvider
 */
public final class RefreshOidcUserReactiveOAuth2AuthorizationSuccessHandler
		implements ReactiveOAuth2AuthorizationSuccessHandler {

	private static final String INVALID_ID_TOKEN_ERROR_CODE = "invalid_id_token";

	private static final String INVALID_NONCE_ERROR_CODE = "invalid_nonce";

	private static final String REFRESH_TOKEN_RESPONSE_ERROR_URI = "https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse";

	// @formatter:off
	private static final Mono<ServerWebExchange> currentServerWebExchangeMono = Mono.deferContextual(Mono::just)
			.filter((c) -> c.hasKey(ServerWebExchange.class))
			.map((c) -> c.get(ServerWebExchange.class));
	// @formatter:on

	private ServerSecurityContextRepository serverSecurityContextRepository = new WebSessionServerSecurityContextRepository();

	private ReactiveJwtDecoderFactory<ClientRegistration> jwtDecoderFactory = new ReactiveOidcIdTokenDecoderFactory();

	private ReactiveOAuth2UserService<OidcUserRequest, OidcUser> userService = new OidcReactiveOAuth2UserService();

	private GrantedAuthoritiesMapper authoritiesMapper = (authorities) -> authorities;

	private Duration clockSkew = Duration.ofSeconds(60);

	@Override
	public Mono<Void> onAuthorizationSuccess(OAuth2AuthorizedClient authorizedClient, Authentication principal,
			Map<String, Object> attributes) {
		// The response must contain the openid scope.
		if (!authorizedClient.getAccessToken().getScopes().contains(OidcScopes.OPENID)) {
			return Mono.empty();
		}
		// The response must contain an id_token.
		String idToken = extractIdToken(attributes);
		if (!StringUtils.hasText(idToken)) {
			return Mono.empty();
		}
		if (!(principal instanceof OAuth2AuthenticationToken authenticationToken)
				|| authenticationToken.getClass() != OAuth2AuthenticationToken.class) {
			// If the application customizes the authentication result, then a custom
			// handler should be provided.
			return Mono.empty();
		}
		// The current principal must be an OidcUser.
		if (!(authenticationToken.getPrincipal() instanceof OidcUser existingOidcUser)) {
			return Mono.empty();
		}
		ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
		// The registrationId must match the one used to log in.
		if (!authenticationToken.getAuthorizedClientRegistrationId().equals(clientRegistration.getRegistrationId())) {
			return Mono.empty();
		}
		// Create, validate OidcIdToken and refresh OidcUser in the SecurityContext.
		return Mono.justOrEmpty((ServerWebExchange) attributes.get(ServerWebExchange.class.getName()))
			.switchIfEmpty(currentServerWebExchangeMono)
			.flatMap((exchange) -> {
				ReactiveJwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(clientRegistration);
				return jwtDecoder.decode(idToken).onErrorMap(JwtException.class, (ex) -> {
					OAuth2Error invalidIdTokenError = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE, ex.getMessage(),
							null);
					return new OAuth2AuthenticationException(invalidIdTokenError, invalidIdTokenError.toString(), ex);
				})
					.map((jwt) -> new OidcIdToken(jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(),
							jwt.getClaims()))
					.doOnNext((oidcIdToken) -> validateIdToken(existingOidcUser, oidcIdToken))
					.flatMap((oidcIdToken) -> {
						OidcUserRequest userRequest = new OidcUserRequest(clientRegistration,
								authorizedClient.getAccessToken(), oidcIdToken);
						return this.userService.loadUser(userRequest);
					})
					.flatMap((oidcUser) -> refreshSecurityContext(exchange, clientRegistration, authenticationToken,
							oidcUser));
			});
	}

	/**
	 * Sets a {@link ServerSecurityContextRepository} to use for refreshing a
	 * {@link SecurityContext}, defaults to
	 * {@link WebSessionServerSecurityContextRepository}.
	 * @param serverSecurityContextRepository the {@link ServerSecurityContextRepository}
	 * to use
	 */
	public void setServerSecurityContextRepository(ServerSecurityContextRepository serverSecurityContextRepository) {
		Assert.notNull(serverSecurityContextRepository, "serverSecurityContextRepository cannot be null");
		this.serverSecurityContextRepository = serverSecurityContextRepository;
	}

	/**
	 * Sets a {@link ReactiveJwtDecoderFactory} to use for decoding refreshed oidc
	 * id-token, defaults to {@link ReactiveOidcIdTokenDecoderFactory}.
	 * @param jwtDecoderFactory the {@link ReactiveJwtDecoderFactory} to use
	 */
	public void setJwtDecoderFactory(ReactiveJwtDecoderFactory<ClientRegistration> jwtDecoderFactory) {
		Assert.notNull(jwtDecoderFactory, "jwtDecoderFactory cannot be null");
		this.jwtDecoderFactory = jwtDecoderFactory;
	}

	/**
	 * Sets a {@link ReactiveOAuth2UserService} to use for loading an {@link OidcUser}
	 * from refreshed oidc id-token, defaults to {@link OidcReactiveOAuth2UserService}.
	 * @param userService the {@link ReactiveOAuth2UserService} to use
	 */
	public void setUserService(ReactiveOAuth2UserService<OidcUserRequest, OidcUser> userService) {
		Assert.notNull(userService, "userService cannot be null");
		this.userService = userService;
	}

	/**
	 * Sets a {@link GrantedAuthoritiesMapper} to use for mapping
	 * {@link GrantedAuthority}s, defaults to no-op implementation.
	 * @param authoritiesMapper the {@link GrantedAuthoritiesMapper} to use
	 */
	public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
		Assert.notNull(authoritiesMapper, "authoritiesMapper cannot be null");
		this.authoritiesMapper = authoritiesMapper;
	}

	/**
	 * Sets the maximum acceptable clock skew, which is used when checking the
	 * {@link OidcIdToken#getIssuedAt()} to match the existing
	 * {@link OidcUser#getIdToken()}'s issuedAt time, defaults to 60 seconds.
	 * @param clockSkew the maximum acceptable clock skew to use
	 */
	public void setClockSkew(Duration clockSkew) {
		Assert.notNull(clockSkew, "clockSkew cannot be null");
		Assert.isTrue(clockSkew.getSeconds() >= 0, "clockSkew must be >= 0");
		this.clockSkew = clockSkew;
	}

	private String extractIdToken(Map<String, Object> attributes) {
		if (attributes.get(OidcParameterNames.ID_TOKEN) instanceof String idToken) {
			return idToken;
		}
		return null;
	}

	private void validateIdToken(OidcUser existingOidcUser, OidcIdToken idToken) {
		// OpenID Connect Core 1.0 - Section 12.2 Successful Refresh Response
		// If an ID Token is returned as a result of a token refresh request, the
		// following requirements apply:
		// its iss Claim Value MUST be the same as in the ID Token issued when the
		// original authentication occurred,
		validateIssuer(existingOidcUser, idToken);
		// its sub Claim Value MUST be the same as in the ID Token issued when the
		// original authentication occurred,
		validateSubject(existingOidcUser, idToken);
		// its iat Claim MUST represent the time that the new ID Token is issued,
		validateIssuedAt(existingOidcUser, idToken);
		// its aud Claim Value MUST be the same as in the ID Token issued when the
		// original authentication occurred,
		validateAudience(existingOidcUser, idToken);
		// if the ID Token contains an auth_time Claim, its value MUST represent the time
		// of the original authentication - not the time that the new ID token is issued,
		validateAuthenticatedAt(existingOidcUser, idToken);
		// it SHOULD NOT have a nonce Claim, even when the ID Token issued at the time of
		// the original authentication contained nonce; however, if it is present, its
		// value MUST be the same as in the ID Token issued at the time of the original
		// authentication,
		validateNonce(existingOidcUser, idToken);
	}

	private void validateIssuer(OidcUser existingOidcUser, OidcIdToken idToken) {
		if (!idToken.getIssuer().toString().equals(existingOidcUser.getIdToken().getIssuer().toString())) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE, "Invalid issuer",
					REFRESH_TOKEN_RESPONSE_ERROR_URI);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
	}

	private void validateSubject(OidcUser existingOidcUser, OidcIdToken idToken) {
		if (!idToken.getSubject().equals(existingOidcUser.getIdToken().getSubject())) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE, "Invalid subject",
					REFRESH_TOKEN_RESPONSE_ERROR_URI);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
	}

	private void validateIssuedAt(OidcUser existingOidcUser, OidcIdToken idToken) {
		if (!idToken.getIssuedAt().isAfter(existingOidcUser.getIdToken().getIssuedAt().minus(this.clockSkew))) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE, "Invalid issued at time",
					REFRESH_TOKEN_RESPONSE_ERROR_URI);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
	}

	private void validateAudience(OidcUser existingOidcUser, OidcIdToken idToken) {
		if (!isValidAudience(existingOidcUser, idToken)) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE, "Invalid audience",
					REFRESH_TOKEN_RESPONSE_ERROR_URI);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
	}

	private boolean isValidAudience(OidcUser existingOidcUser, OidcIdToken idToken) {
		List<String> idTokenAudiences = idToken.getAudience();
		Set<String> oidcUserAudiences = new HashSet<>(existingOidcUser.getIdToken().getAudience());
		if (idTokenAudiences.size() != oidcUserAudiences.size()) {
			return false;
		}
		for (String audience : idTokenAudiences) {
			if (!oidcUserAudiences.contains(audience)) {
				return false;
			}
		}
		return true;
	}

	private void validateAuthenticatedAt(OidcUser existingOidcUser, OidcIdToken idToken) {
		if (idToken.getAuthenticatedAt() == null) {
			return;
		}
		if (!idToken.getAuthenticatedAt().equals(existingOidcUser.getIdToken().getAuthenticatedAt())) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE, "Invalid authenticated at time",
					REFRESH_TOKEN_RESPONSE_ERROR_URI);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
	}

	private void validateNonce(OidcUser existingOidcUser, OidcIdToken idToken) {
		if (!StringUtils.hasText(idToken.getNonce())) {
			return;
		}
		if (!idToken.getNonce().equals(existingOidcUser.getIdToken().getNonce())) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_NONCE_ERROR_CODE, "Invalid nonce",
					REFRESH_TOKEN_RESPONSE_ERROR_URI);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
	}

	private Mono<Void> refreshSecurityContext(ServerWebExchange exchange, ClientRegistration clientRegistration,
			OAuth2AuthenticationToken authenticationToken, OidcUser oidcUser) {
		Collection<? extends GrantedAuthority> mappedAuthorities = this.authoritiesMapper
			.mapAuthorities(oidcUser.getAuthorities());
		OAuth2AuthenticationToken authenticationResult = new OAuth2AuthenticationToken(oidcUser, mappedAuthorities,
				clientRegistration.getRegistrationId());
		authenticationResult.setDetails(authenticationToken.getDetails());
		SecurityContext securityContext = new SecurityContextImpl(authenticationResult);
		return this.serverSecurityContextRepository.save(exchange, securityContext);
	}

}
