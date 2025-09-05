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

package org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import com.nimbusds.jose.jwk.JWK;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeActor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimNames;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.util.CollectionUtils;

/**
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 1.3
 */
final class DefaultOAuth2TokenCustomizers {

	private DefaultOAuth2TokenCustomizers() {
	}

	static OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
		return (context) -> context.getClaims().claims((claims) -> customize(context, claims));
	}

	static OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer() {
		return (context) -> context.getClaims().claims((claims) -> customize(context, claims));
	}

	private static void customize(OAuth2TokenContext tokenContext, Map<String, Object> claims) {
		Map<String, Object> cnfClaims = null;

		// Add 'cnf' claim for Mutual-TLS Client Certificate-Bound Access Tokens
		if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenContext.getTokenType())
				&& tokenContext.getAuthorizationGrant() != null && tokenContext.getAuthorizationGrant()
					.getPrincipal() instanceof OAuth2ClientAuthenticationToken clientAuthentication) {

			if ((ClientAuthenticationMethod.TLS_CLIENT_AUTH.equals(clientAuthentication.getClientAuthenticationMethod())
					|| ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH
						.equals(clientAuthentication.getClientAuthenticationMethod()))
					&& tokenContext.getRegisteredClient().getTokenSettings().isX509CertificateBoundAccessTokens()) {

				X509Certificate[] clientCertificateChain = (X509Certificate[]) clientAuthentication.getCredentials();
				try {
					String sha256Thumbprint = computeSHA256Thumbprint(clientCertificateChain[0]);
					cnfClaims = new HashMap<>();
					cnfClaims.put("x5t#S256", sha256Thumbprint);
				}
				catch (Exception ex) {
					OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
							"Failed to compute SHA-256 Thumbprint for client X509Certificate.", null);
					throw new OAuth2AuthenticationException(error, ex);
				}
			}
		}

		// Add 'cnf' claim for OAuth 2.0 Demonstrating Proof of Possession (DPoP)
		Jwt dPoPProofJwt = tokenContext.get(OAuth2TokenContext.DPOP_PROOF_KEY);
		if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenContext.getTokenType()) && dPoPProofJwt != null) {
			JWK jwk = null;
			@SuppressWarnings("unchecked")
			Map<String, Object> jwkJson = (Map<String, Object>) dPoPProofJwt.getHeaders().get("jwk");
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

			try {
				String sha256Thumbprint = jwk.computeThumbprint().toString();
				if (cnfClaims == null) {
					cnfClaims = new HashMap<>();
				}
				cnfClaims.put("jkt", sha256Thumbprint);
			}
			catch (Exception ex) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
						"Failed to compute SHA-256 Thumbprint for DPoP Proof PublicKey.", null);
				throw new OAuth2AuthenticationException(error, ex);
			}
		}

		if (!CollectionUtils.isEmpty(cnfClaims)) {
			claims.put("cnf", cnfClaims);
		}

		// Add 'act' claim for delegation use case of Token Exchange Grant.
		// If more than one actor is present, we create a chain of delegation by nesting
		// "act" claims.
		if (tokenContext
			.getPrincipal() instanceof OAuth2TokenExchangeCompositeAuthenticationToken compositeAuthenticationToken) {
			Map<String, Object> currentClaims = claims;
			for (OAuth2TokenExchangeActor actor : compositeAuthenticationToken.getActors()) {
				Map<String, Object> actorClaims = actor.getClaims();
				Map<String, Object> actClaim = new LinkedHashMap<>();
				actClaim.put(OAuth2TokenClaimNames.ISS, actorClaims.get(OAuth2TokenClaimNames.ISS));
				actClaim.put(OAuth2TokenClaimNames.SUB, actorClaims.get(OAuth2TokenClaimNames.SUB));
				currentClaims.put("act", Collections.unmodifiableMap(actClaim));
				currentClaims = actClaim;
			}
		}
	}

	private static String computeSHA256Thumbprint(X509Certificate x509Certificate) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(x509Certificate.getEncoded());
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

}
