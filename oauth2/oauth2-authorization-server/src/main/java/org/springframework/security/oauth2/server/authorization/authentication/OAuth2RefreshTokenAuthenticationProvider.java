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

package org.springframework.security.oauth2.server.authorization.authentication;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import com.nimbusds.jose.jwk.JWK;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Refresh Token Grant.
 *
 * @author Alexey Nesterov
 * @author Joe Grandja
 * @author Anoop Garlapati
 * @since 7.0
 * @see OAuth2RefreshTokenAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see OAuth2AuthorizationService
 * @see OAuth2TokenGenerator
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc6749#section-1.5">Section 1.5 Refresh Token
 * Grant</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc6749#section-6">Section 6 Refreshing an
 * Access Token</a>
 */
public final class OAuth2RefreshTokenAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

	private final Log logger = LogFactory.getLog(getClass());

	private final OAuth2AuthorizationService authorizationService;

	private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

	/**
	 * Constructs an {@code OAuth2RefreshTokenAuthenticationProvider} using the provided
	 * parameters.
	 * @param authorizationService the authorization service
	 * @param tokenGenerator the token generator
	 */
	public OAuth2RefreshTokenAuthenticationProvider(OAuth2AuthorizationService authorizationService,
			OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
		this.authorizationService = authorizationService;
		this.tokenGenerator = tokenGenerator;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2RefreshTokenAuthenticationToken refreshTokenAuthentication = (OAuth2RefreshTokenAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils
			.getAuthenticatedClientElseThrowInvalidClient(refreshTokenAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved registered client");
		}

		OAuth2Authorization authorization = this.authorizationService
			.findByToken(refreshTokenAuthentication.getRefreshToken(), OAuth2TokenType.REFRESH_TOKEN);
		if (authorization == null) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug("Invalid request: refresh_token is invalid");
			}
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved authorization with refresh token");
		}

		if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format(
						"Invalid request: requested grant_type is not allowed" + " for registered client '%s'",
						registeredClient.getId()));
			}
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
		}

		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
		if (!refreshToken.isActive()) {
			// As per https://tools.ietf.org/html/rfc6749#section-5.2
			// invalid_grant: The provided authorization grant (e.g., authorization code,
			// resource owner credentials) or refresh token is invalid, expired, revoked
			// [...].
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format(
						"Invalid request: refresh_token is not active" + " for registered client '%s'",
						registeredClient.getId()));
			}
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		// As per https://tools.ietf.org/html/rfc6749#section-6
		// The requested scope MUST NOT include any scope not originally granted by the
		// resource owner,
		// and if omitted is treated as equal to the scope originally granted by the
		// resource owner.
		Set<String> scopes = refreshTokenAuthentication.getScopes();
		Set<String> authorizedScopes = authorization.getAuthorizedScopes();
		if (!authorizedScopes.containsAll(scopes)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
		}

		// Verify the DPoP Proof (if available)
		Jwt dPoPProof = DPoPProofVerifier.verifyIfAvailable(refreshTokenAuthentication);

		if (dPoPProof != null
				&& clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {
			// For public clients, verify the DPoP Proof public key is same as (current)
			// access token public key binding
			Map<String, Object> accessTokenClaims = authorization.getAccessToken().getClaims();
			verifyDPoPProofPublicKey(dPoPProof, () -> accessTokenClaims);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated token request parameters");
		}

		if (scopes.isEmpty()) {
			scopes = authorizedScopes;
		}

		// @formatter:off
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(authorization.getAttribute(Principal.class.getName()))
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.authorization(authorization)
				.authorizedScopes(scopes)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrant(refreshTokenAuthentication);
		// @formatter:on
		if (dPoPProof != null) {
			tokenContextBuilder.put(OAuth2TokenContext.DPOP_PROOF_KEY, dPoPProof);
		}

		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);

		// ----- Access token -----
		OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
		OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
		if (generatedAccessToken == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the access token.", ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Generated access token");
		}

		OAuth2AccessToken accessToken = OAuth2AuthenticationProviderUtils.accessToken(authorizationBuilder,
				generatedAccessToken, tokenContext);

		// ----- Refresh token -----
		OAuth2RefreshToken currentRefreshToken = refreshToken.getToken();
		if (!registeredClient.getTokenSettings().isReuseRefreshTokens()) {
			// @formatter:off
			tokenContext = tokenContextBuilder
					.tokenType(OAuth2TokenType.REFRESH_TOKEN)
					.authorization(authorizationBuilder.build())	// Refresh token generator/customizer may need access to the access token
					.build();
			// @formatter:on
			OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
			if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
						"The token generator failed to generate the refresh token.", ERROR_URI);
				throw new OAuth2AuthenticationException(error);
			}

			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Generated refresh token");
			}

			currentRefreshToken = (OAuth2RefreshToken) generatedRefreshToken;
			authorizationBuilder.refreshToken(currentRefreshToken);
		}

		// ----- ID token -----
		OidcIdToken idToken;
		if (authorizedScopes.contains(OidcScopes.OPENID)) {
			// @formatter:off
			tokenContext = tokenContextBuilder
					.tokenType(ID_TOKEN_TOKEN_TYPE)
					.authorization(authorizationBuilder.build())	// ID token customizer may need access to the access token and/or refresh token
					.build();
			// @formatter:on
			OAuth2Token generatedIdToken = this.tokenGenerator.generate(tokenContext);
			if (!(generatedIdToken instanceof Jwt)) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
						"The token generator failed to generate the ID token.", ERROR_URI);
				throw new OAuth2AuthenticationException(error);
			}

			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Generated id token");
			}

			idToken = new OidcIdToken(generatedIdToken.getTokenValue(), generatedIdToken.getIssuedAt(),
					generatedIdToken.getExpiresAt(), ((Jwt) generatedIdToken).getClaims());
			authorizationBuilder.token(idToken,
					(metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()));
		}
		else {
			idToken = null;
		}

		authorization = authorizationBuilder.build();

		this.authorizationService.save(authorization);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Saved authorization");
		}

		Map<String, Object> additionalParameters = Collections.emptyMap();
		if (idToken != null) {
			additionalParameters = new HashMap<>();
			additionalParameters.put(OidcParameterNames.ID_TOKEN, idToken.getTokenValue());
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated token request");
		}

		OAuth2AccessTokenAuthenticationToken accessTokenAuthenticationResult = new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken, currentRefreshToken, additionalParameters);
		accessTokenAuthenticationResult.setDetails(refreshTokenAuthentication.getDetails());
		return accessTokenAuthenticationResult;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2RefreshTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static void verifyDPoPProofPublicKey(Jwt dPoPProof, ClaimAccessor accessTokenClaims) {
		JWK jwk = null;
		@SuppressWarnings("unchecked")
		Map<String, Object> jwkJson = (Map<String, Object>) dPoPProof.getHeaders().get("jwk");
		try {
			jwk = JWK.parse(jwkJson);
		}
		catch (Exception ignored) {
		}
		if (jwk == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF,
					"jwk header is missing or invalid.", null);
			throw new OAuth2AuthenticationException(error);
		}

		String jwkThumbprint;
		try {
			jwkThumbprint = jwk.computeThumbprint().toString();
		}
		catch (Exception ex) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF,
					"Failed to compute SHA-256 Thumbprint for jwk.", null);
			throw new OAuth2AuthenticationException(error);
		}

		String jwkThumbprintClaim = null;
		Map<String, Object> confirmationMethodClaim = accessTokenClaims.getClaimAsMap("cnf");
		if (!CollectionUtils.isEmpty(confirmationMethodClaim) && confirmationMethodClaim.containsKey("jkt")) {
			jwkThumbprintClaim = (String) confirmationMethodClaim.get("jkt");
		}
		if (jwkThumbprintClaim == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF, "jkt claim is missing.", null);
			throw new OAuth2AuthenticationException(error);
		}

		if (!jwkThumbprint.equals(jwkThumbprintClaim)) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF, "jwk header is invalid.", null);
			throw new OAuth2AuthenticationException(error);
		}
	}

}
