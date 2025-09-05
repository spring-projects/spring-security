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

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.DPoPProofContext;
import org.springframework.security.oauth2.jwt.DPoPProofJwtDecoderFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.util.StringUtils;

/**
 * A verifier for DPoP Proof {@link Jwt}'s.
 *
 * @author Joe Grandja
 * @since 1.5
 * @see DPoPProofJwtDecoderFactory
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc9449">RFC 9449
 * OAuth 2.0 Demonstrating Proof of Possession (DPoP)</a>
 */
final class DPoPProofVerifier {

	private static final JwtDecoderFactory<DPoPProofContext> dPoPProofVerifierFactory = new DPoPProofJwtDecoderFactory();

	private DPoPProofVerifier() {
	}

	static Jwt verifyIfAvailable(OAuth2AuthorizationGrantAuthenticationToken authorizationGrantAuthentication) {
		String dPoPProof = (String) authorizationGrantAuthentication.getAdditionalParameters().get("dpop_proof");
		if (!StringUtils.hasText(dPoPProof)) {
			return null;
		}

		String method = (String) authorizationGrantAuthentication.getAdditionalParameters().get("dpop_method");
		String targetUri = (String) authorizationGrantAuthentication.getAdditionalParameters().get("dpop_target_uri");

		Jwt dPoPProofJwt;
		try {
			// @formatter:off
			DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof)
					.method(method)
					.targetUri(targetUri)
					.build();
			// @formatter:on
			JwtDecoder dPoPProofVerifier = dPoPProofVerifierFactory.createDecoder(dPoPProofContext);
			dPoPProofJwt = dPoPProofVerifier.decode(dPoPProof);
		}
		catch (Exception ex) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF), ex);
		}

		return dPoPProofJwt;
	}

}
