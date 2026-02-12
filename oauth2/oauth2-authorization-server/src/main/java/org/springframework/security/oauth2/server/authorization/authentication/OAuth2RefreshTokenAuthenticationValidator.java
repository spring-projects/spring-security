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

import java.util.Map;
import java.util.function.Consumer;

import com.nimbusds.jose.jwk.JWK;

import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.CollectionUtils;

/**
 * A {@code Consumer} that validates an {@link OAuth2RefreshTokenAuthenticationContext}
 * and acts as the default
 * {@link OAuth2RefreshTokenAuthenticationProvider#setAuthenticationValidator(Consumer)
 * authentication validator} for the Refresh Token grant.
 * <p>
 * The default implementation validates a DPoP proof if present and throws
 * {@link OAuth2AuthenticationException} on failure.
 * </p>
 *
 * @author Andrey Litvitski
 * @since 7.0.0
 * @see OAuth2RefreshTokenAuthenticationContext
 * @see OAuth2RefreshTokenAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
public final class OAuth2RefreshTokenAuthenticationValidator
		implements Consumer<OAuth2RefreshTokenAuthenticationContext> {

	public static final Consumer<OAuth2RefreshTokenAuthenticationContext> DEFAULT_VALIDATOR = OAuth2RefreshTokenAuthenticationValidator::validateDefault;

	private final Consumer<OAuth2RefreshTokenAuthenticationContext> authenticationValidator = DEFAULT_VALIDATOR;

	@Override
	public void accept(OAuth2RefreshTokenAuthenticationContext context) {
		this.authenticationValidator.accept(context);
	}

	private static void validateDefault(OAuth2RefreshTokenAuthenticationContext context) {
		Jwt dPoPProof;
		if (context.getDPoPProof() == null) {
			dPoPProof = DPoPProofVerifier.verifyIfAvailable(context.getAuthentication());
		}
		else {
			dPoPProof = context.getDPoPProof();
		}
		if (dPoPProof == null || !context.getClientPrincipal()
			.getClientAuthenticationMethod()
			.equals(ClientAuthenticationMethod.NONE)) {
			return;
		}
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
		Map<String, Object> accessTokenClaimsMap = context.getAuthorization().getAccessToken().getClaims();
		ClaimAccessor accessTokenClaims = () -> accessTokenClaimsMap;
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
