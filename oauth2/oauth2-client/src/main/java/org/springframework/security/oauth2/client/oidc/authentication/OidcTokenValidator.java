/*
 * Copyright 2002-2018 the original author or authors.
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

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.util.CollectionUtils;

import java.net.URL;
import java.time.Instant;
import java.util.List;

/**
 * @author Rob Winch
 * @since 5.1
 */
final class OidcTokenValidator {
	private static final String INVALID_ID_TOKEN_ERROR_CODE = "invalid_id_token";

	static void validateIdToken(OidcIdToken idToken, ClientRegistration clientRegistration) {
		// 3.1.3.7  ID Token Validation
		// http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

		// Validate REQUIRED Claims
		URL issuer = idToken.getIssuer();
		if (issuer == null) {
			throwInvalidIdTokenException();
		}
		String subject = idToken.getSubject();
		if (subject == null) {
			throwInvalidIdTokenException();
		}
		List<String> audience = idToken.getAudience();
		if (CollectionUtils.isEmpty(audience)) {
			throwInvalidIdTokenException();
		}
		Instant expiresAt = idToken.getExpiresAt();
		if (expiresAt == null) {
			throwInvalidIdTokenException();
		}
		Instant issuedAt = idToken.getIssuedAt();
		if (issuedAt == null) {
			throwInvalidIdTokenException();
		}

		// 2. The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery)
		// MUST exactly match the value of the iss (issuer) Claim.
		// TODO Depends on gh-4413

		// 3. The Client MUST validate that the aud (audience) Claim contains its client_id value
		// registered at the Issuer identified by the iss (issuer) Claim as an audience.
		// The aud (audience) Claim MAY contain an array with more than one element.
		// The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience,
		// or if it contains additional audiences not trusted by the Client.
		if (!audience.contains(clientRegistration.getClientId())) {
			throwInvalidIdTokenException();
		}

		// 4. If the ID Token contains multiple audiences,
		// the Client SHOULD verify that an azp Claim is present.
		String authorizedParty = idToken.getAuthorizedParty();
		if (audience.size() > 1 && authorizedParty == null) {
			throwInvalidIdTokenException();
		}

		// 5. If an azp (authorized party) Claim is present,
		// the Client SHOULD verify that its client_id is the Claim Value.
		if (authorizedParty != null && !authorizedParty.equals(clientRegistration.getClientId())) {
			throwInvalidIdTokenException();
		}

		// 7. The alg value SHOULD be the default of RS256 or the algorithm sent by the Client
		// in the id_token_signed_response_alg parameter during Registration.
		// TODO Depends on gh-4413

		// 9. The current time MUST be before the time represented by the exp Claim.
		Instant now = Instant.now();
		if (!now.isBefore(expiresAt)) {
			throwInvalidIdTokenException();
		}

		// 10. The iat Claim can be used to reject tokens that were issued too far away from the current time,
		// limiting the amount of time that nonces need to be stored to prevent attacks.
		// The acceptable range is Client specific.
		Instant maxIssuedAt = now.plusSeconds(30);
		if (issuedAt.isAfter(maxIssuedAt)) {
			throwInvalidIdTokenException();
		}

		// 11. If a nonce value was sent in the Authentication Request,
		// a nonce Claim MUST be present and its value checked to verify
		// that it is the same value as the one that was sent in the Authentication Request.
		// The Client SHOULD check the nonce value for replay attacks.
		// The precise method for detecting replay attacks is Client specific.
		// TODO Depends on gh-4442

	}

	private static void throwInvalidIdTokenException() {
		OAuth2Error invalidIdTokenError = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE);
		throw new OAuth2AuthenticationException(invalidIdTokenError, invalidIdTokenError.toString());
	}

	private OidcTokenValidator() {}
}
