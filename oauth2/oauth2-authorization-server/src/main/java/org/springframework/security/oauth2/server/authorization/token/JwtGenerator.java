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

package org.springframework.security.oauth2.server.authorization.token;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * An {@link OAuth2TokenGenerator} that generates a {@link Jwt} used for an
 * {@link OAuth2AccessToken} or {@link OidcIdToken}.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2TokenGenerator
 * @see Jwt
 * @see JwtEncoder
 * @see OAuth2TokenCustomizer
 * @see JwtEncodingContext
 * @see OAuth2AccessToken
 * @see OidcIdToken
 */
public final class JwtGenerator implements OAuth2TokenGenerator<Jwt> {

	private final JwtEncoder jwtEncoder;

	private @Nullable OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;

	private Clock clock = Clock.systemUTC();

	/**
	 * Constructs a {@code JwtGenerator} using the provided parameters.
	 * @param jwtEncoder the jwt encoder
	 */
	public JwtGenerator(JwtEncoder jwtEncoder) {
		Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
		this.jwtEncoder = jwtEncoder;
	}

	@Override
	public @Nullable Jwt generate(OAuth2TokenContext context) {
		// @formatter:off
		if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) &&
				!OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
			return null;
		}
		if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType()) &&
				!OAuth2TokenFormat.SELF_CONTAINED.equals(context.getRegisteredClient().getTokenSettings().getAccessTokenFormat())) {
			return null;
		}
		// @formatter:on

		RegisteredClient registeredClient = context.getRegisteredClient();
		String issuer = context.getAuthorizationServerContext().getIssuer();
		Instant issuedAt = this.clock.instant();
		Instant expiresAt;
		JwsAlgorithm jwsAlgorithm = SignatureAlgorithm.RS256;
		if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
			// TODO Allow configuration for ID Token time-to-live
			expiresAt = issuedAt.plus(30, ChronoUnit.MINUTES);
			jwsAlgorithm = registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm();
		}
		else {
			expiresAt = issuedAt.plus(registeredClient.getTokenSettings().getAccessTokenTimeToLive());
		}

		Authentication principal = context.getPrincipal();
		Assert.notNull(principal, "principal cannot be null");

		AuthorizationGrantType authorizationGrantType = context.getAuthorizationGrantType();
		Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");

		// @formatter:off
		JwtClaimsSet.Builder claimsBuilder = JwtClaimsSet.builder()
				.issuer(issuer)
				.subject(principal.getName())
				.audience(Collections.singletonList(registeredClient.getClientId()))
				.issuedAt(issuedAt)
				.expiresAt(expiresAt)
				.id(UUID.randomUUID().toString());
		if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
			claimsBuilder.notBefore(issuedAt);
			if (!CollectionUtils.isEmpty(context.getAuthorizedScopes())) {
				claimsBuilder.claim(OAuth2ParameterNames.SCOPE, context.getAuthorizedScopes());
			}
		}
		else if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
			claimsBuilder.claim(IdTokenClaimNames.AZP, registeredClient.getClientId());
			if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationGrantType)) {
				OAuth2Authorization authorization = context.getAuthorization();
				Assert.notNull(authorization, "authorization cannot be null");
				OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
						OAuth2AuthorizationRequest.class.getName());
				Assert.notNull(authorizationRequest, "authorizationRequest cannot be null");
				String nonce = (String) authorizationRequest.getAdditionalParameters().get(OidcParameterNames.NONCE);
				if (StringUtils.hasText(nonce)) {
					claimsBuilder.claim(IdTokenClaimNames.NONCE, nonce);
				}
				SessionInformation sessionInformation = context.get(SessionInformation.class);
				if (sessionInformation != null) {
					claimsBuilder.claim("sid", sessionInformation.getSessionId());
					claimsBuilder.claim(IdTokenClaimNames.AUTH_TIME, getAuthenticationTime(principal));
				}
			}
			else if (AuthorizationGrantType.REFRESH_TOKEN.equals(authorizationGrantType)) {
				OAuth2Authorization authorization = context.getAuthorization();
				Assert.notNull(authorization, "authorization cannot be null");
				OAuth2Authorization.Token<OidcIdToken> authorizedIdToken = authorization.getToken(OidcIdToken.class);
				Assert.notNull(authorizedIdToken, "authorizedIdToken cannot be null");
				OidcIdToken currentIdToken = authorizedIdToken.getToken();
				String sidClaim = currentIdToken.getClaim("sid");
				if (sidClaim != null) {
					claimsBuilder.claim("sid", sidClaim);
				}
				Date authTimeClaim = currentIdToken.getClaim(IdTokenClaimNames.AUTH_TIME);
				if (authTimeClaim != null) {
					claimsBuilder.claim(IdTokenClaimNames.AUTH_TIME, authTimeClaim);
				}
			}
		}
		// @formatter:on

		JwsHeader.Builder jwsHeaderBuilder = JwsHeader.with(jwsAlgorithm);

		if (this.jwtCustomizer != null) {
			// @formatter:off
			JwtEncodingContext.Builder jwtContextBuilder = JwtEncodingContext.with(jwsHeaderBuilder, claimsBuilder)
					.registeredClient(context.getRegisteredClient())
					.principal(principal)
					.authorizationServerContext(context.getAuthorizationServerContext())
					.authorizedScopes(context.getAuthorizedScopes())
					.tokenType(context.getTokenType())
					.authorizationGrantType(authorizationGrantType);
			if (context.getAuthorization() != null) {
				jwtContextBuilder.authorization(context.getAuthorization());
			}
			if (context.getAuthorizationGrant() != null) {
				jwtContextBuilder.authorizationGrant(context.getAuthorizationGrant());
			}
			if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
				SessionInformation sessionInformation = context.get(SessionInformation.class);
				if (sessionInformation != null) {
					jwtContextBuilder.put(SessionInformation.class, sessionInformation);
				}
			}
			if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				Jwt dPoPProofJwt = context.get(OAuth2TokenContext.DPOP_PROOF_KEY);
				if (dPoPProofJwt != null) {
					jwtContextBuilder.put(OAuth2TokenContext.DPOP_PROOF_KEY, dPoPProofJwt);
				}
			}
			// @formatter:on

			JwtEncodingContext jwtContext = jwtContextBuilder.build();
			this.jwtCustomizer.customize(jwtContext);
		}

		JwsHeader jwsHeader = jwsHeaderBuilder.build();
		JwtClaimsSet claims = claimsBuilder.build();

		Jwt jwt = this.jwtEncoder.encode(JwtEncoderParameters.from(jwsHeader, claims));

		return jwt;
	}

	/**
	 * Sets the {@link OAuth2TokenCustomizer} that customizes the
	 * {@link JwtEncodingContext#getJwsHeader() JWS headers} and/or
	 * {@link JwtEncodingContext#getClaims() claims} for the generated {@link Jwt}.
	 * @param jwtCustomizer the {@link OAuth2TokenCustomizer} that customizes the headers
	 * and/or claims for the generated {@code Jwt}
	 */
	public void setJwtCustomizer(OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer) {
		Assert.notNull(jwtCustomizer, "jwtCustomizer cannot be null");
		this.jwtCustomizer = jwtCustomizer;
	}

	/**
	 * Sets the {@link Clock} used when obtaining the current instant via
	 * {@link Clock#instant()}.
	 * @param clock the {@link Clock} used when obtaining the current instant via
	 * {@link Clock#instant()}
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

	static Date getAuthenticationTime(Authentication authentication) {
		Instant authenticationTime = null;
		for (GrantedAuthority grantedAuthority : authentication.getAuthorities()) {
			if (grantedAuthority instanceof FactorGrantedAuthority factorGrantedAuthority) {
				if (authenticationTime == null || factorGrantedAuthority.getIssuedAt().isAfter(authenticationTime)) {
					authenticationTime = factorGrantedAuthority.getIssuedAt();
				}
			}
		}
		Assert.notNull(authenticationTime, "authenticationTime cannot be null");
		return Date.from(authenticationTime);
	}

}
