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

package org.springframework.security.oauth2.server.resource.authentication;

import java.time.Instant;
import java.util.Map;

import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.DPoPProofContext;
import org.springframework.security.oauth2.jwt.DPoPProofJwtDecoderFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation that is responsible for authenticating
 * a DPoP-bound access token for a protected resource request.
 *
 * @author Joe Grandja
 * @since 6.5
 * @see DPoPAuthenticationToken
 * @see DPoPProofJwtDecoderFactory
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc9449">RFC 9449
 * OAuth 2.0 Demonstrating Proof of Possession (DPoP)</a>
 */
public final class DPoPAuthenticationProvider implements AuthenticationProvider {

	private final AuthenticationManager tokenAuthenticationManager;

	private JwtDecoderFactory<DPoPProofContext> dPoPProofVerifierFactory;

	/**
	 * Constructs a {@code DPoPAuthenticationProvider} using the provided parameters.
	 * @param tokenAuthenticationManager the {@link AuthenticationManager} used to
	 * authenticate the DPoP-bound access token
	 */
	public DPoPAuthenticationProvider(AuthenticationManager tokenAuthenticationManager) {
		Assert.notNull(tokenAuthenticationManager, "tokenAuthenticationManager cannot be null");
		this.tokenAuthenticationManager = tokenAuthenticationManager;
		this.dPoPProofVerifierFactory = new DPoPProofJwtDecoderFactory();
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		DPoPAuthenticationToken dPoPAuthenticationToken = (DPoPAuthenticationToken) authentication;

		BearerTokenAuthenticationToken accessTokenAuthenticationRequest = new BearerTokenAuthenticationToken(
				dPoPAuthenticationToken.getAccessToken());
		Authentication accessTokenAuthenticationResult = this.tokenAuthenticationManager
			.authenticate(accessTokenAuthenticationRequest);

		AbstractOAuth2TokenAuthenticationToken<OAuth2Token> accessTokenAuthentication = null;
		if (accessTokenAuthenticationResult instanceof AbstractOAuth2TokenAuthenticationToken) {
			accessTokenAuthentication = (AbstractOAuth2TokenAuthenticationToken) accessTokenAuthenticationResult;
		}
		if (accessTokenAuthentication == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
					"Unable to authenticate the DPoP-bound access token.", null);
			throw new OAuth2AuthenticationException(error);
		}

		OAuth2AccessTokenClaims accessToken = new OAuth2AccessTokenClaims(accessTokenAuthentication.getToken(),
				accessTokenAuthentication.getTokenAttributes());

		DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPAuthenticationToken.getDPoPProof())
			.accessToken(accessToken)
			.method(dPoPAuthenticationToken.getMethod())
			.targetUri(dPoPAuthenticationToken.getResourceUri())
			.build();
		JwtDecoder dPoPProofVerifier = this.dPoPProofVerifierFactory.createDecoder(dPoPProofContext);

		try {
			dPoPProofVerifier.decode(dPoPProofContext.getDPoPProof());
		}
		catch (Exception ex) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF);
			throw new OAuth2AuthenticationException(error, ex);
		}

		return accessTokenAuthenticationResult;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return DPoPAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Sets the {@link JwtDecoderFactory} that provides a {@link JwtDecoder} for the
	 * specified {@link DPoPProofContext} and is used for authenticating a DPoP Proof
	 * {@link Jwt}. The default factory is {@link DPoPProofJwtDecoderFactory}.
	 * @param dPoPProofVerifierFactory the {@link JwtDecoderFactory} that provides a
	 * {@link JwtDecoder} for the specified {@link DPoPProofContext}
	 */
	public void setDPoPProofVerifierFactory(JwtDecoderFactory<DPoPProofContext> dPoPProofVerifierFactory) {
		Assert.notNull(dPoPProofVerifierFactory, "dPoPProofVerifierFactory cannot be null");
		this.dPoPProofVerifierFactory = dPoPProofVerifierFactory;
	}

	private static final class OAuth2AccessTokenClaims implements OAuth2Token, ClaimAccessor {

		private final OAuth2Token accessToken;

		private final Map<String, Object> claims;

		private OAuth2AccessTokenClaims(OAuth2Token accessToken, Map<String, Object> claims) {
			this.accessToken = accessToken;
			this.claims = claims;
		}

		@Override
		public String getTokenValue() {
			return this.accessToken.getTokenValue();
		}

		@Override
		public @Nullable Instant getIssuedAt() {
			return this.accessToken.getIssuedAt();
		}

		@Override
		public @Nullable Instant getExpiresAt() {
			return this.accessToken.getExpiresAt();
		}

		@Override
		public Map<String, Object> getClaims() {
			return this.claims;
		}

	}

}
