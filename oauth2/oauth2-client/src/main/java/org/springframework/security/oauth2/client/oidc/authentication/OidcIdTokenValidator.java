/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.oidc.authentication;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.net.URL;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * An {@link OAuth2TokenValidator} responsible for
 * validating the claims in an {@link OidcIdToken ID Token}.
 *
 * @author Rob Winch
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2TokenValidator
 * @see Jwt
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation">ID Token Validation</a>
 */
public final class OidcIdTokenValidator implements OAuth2TokenValidator<Jwt> {
	private final ClientRegistration clientRegistration;

	public OidcIdTokenValidator(ClientRegistration clientRegistration) {
		Assert.notNull(clientRegistration, "clientRegistration cannot be null");
		this.clientRegistration = clientRegistration;
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt idToken) {
		// 3.1.3.7  ID Token Validation
		// http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation

		Map<String, Object> invalidClaims = validateRequiredClaims(idToken);
		if (!invalidClaims.isEmpty()) {
			return OAuth2TokenValidatorResult.failure(invalidIdToken(invalidClaims));
		}

		// 2. The Issuer Identifier for the OpenID Provider (which is typically obtained during Discovery)
		// MUST exactly match the value of the iss (issuer) Claim.
		// TODO Depends on gh-4413

		// 3. The Client MUST validate that the aud (audience) Claim contains its client_id value
		// registered at the Issuer identified by the iss (issuer) Claim as an audience.
		// The aud (audience) Claim MAY contain an array with more than one element.
		// The ID Token MUST be rejected if the ID Token does not list the Client as a valid audience,
		// or if it contains additional audiences not trusted by the Client.
		if (!idToken.getAudience().contains(this.clientRegistration.getClientId())) {
			invalidClaims.put(IdTokenClaimNames.AUD, idToken.getAudience());
		}

		// 4. If the ID Token contains multiple audiences,
		// the Client SHOULD verify that an azp Claim is present.
		String authorizedParty = idToken.getClaimAsString(IdTokenClaimNames.AZP);
		if (idToken.getAudience().size() > 1 && authorizedParty == null) {
			invalidClaims.put(IdTokenClaimNames.AZP, authorizedParty);
		}

		// 5. If an azp (authorized party) Claim is present,
		// the Client SHOULD verify that its client_id is the Claim Value.
		if (authorizedParty != null && !authorizedParty.equals(this.clientRegistration.getClientId())) {
			invalidClaims.put(IdTokenClaimNames.AZP, authorizedParty);
		}

		// 7. The alg value SHOULD be the default of RS256 or the algorithm sent by the Client
		// in the id_token_signed_response_alg parameter during Registration.
		// TODO Depends on gh-4413

		// 9. The current time MUST be before the time represented by the exp Claim.
		Instant now = Instant.now();
		if (!now.isBefore(idToken.getExpiresAt())) {
			invalidClaims.put(IdTokenClaimNames.EXP, idToken.getExpiresAt());
		}

		// 10. The iat Claim can be used to reject tokens that were issued too far away from the current time,
		// limiting the amount of time that nonces need to be stored to prevent attacks.
		// The acceptable range is Client specific.
		Instant maxIssuedAt = now.plusSeconds(30);
		if (idToken.getIssuedAt().isAfter(maxIssuedAt)) {
			invalidClaims.put(IdTokenClaimNames.IAT, idToken.getIssuedAt());
		}

		// 11. If a nonce value was sent in the Authentication Request,
		// a nonce Claim MUST be present and its value checked to verify
		// that it is the same value as the one that was sent in the Authentication Request.
		// The Client SHOULD check the nonce value for replay attacks.
		// The precise method for detecting replay attacks is Client specific.
		// TODO Depends on gh-4442

		if (!invalidClaims.isEmpty()) {
			return OAuth2TokenValidatorResult.failure(invalidIdToken(invalidClaims));
		}

		return OAuth2TokenValidatorResult.success();
	}

	private static OAuth2Error invalidIdToken(Map<String, Object> invalidClaims) {
		String claimsDetail = invalidClaims.entrySet().stream()
				.map(it -> it.getKey() + " (" + it.getValue() + ")")
				.collect(Collectors.joining(", "));
		return new OAuth2Error("invalid_id_token",
				"The ID Token contains invalid claims: " + claimsDetail,
				"https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation");
	}

	private static Map<String, Object> validateRequiredClaims(Jwt idToken) {
		Map<String, Object> requiredClaims = new HashMap<>();

		URL issuer = idToken.getIssuer();
		if (issuer == null) {
			requiredClaims.put(IdTokenClaimNames.ISS, issuer);
		}
		String subject = idToken.getSubject();
		if (subject == null) {
			requiredClaims.put(IdTokenClaimNames.SUB, subject);
		}
		List<String> audience = idToken.getAudience();
		if (CollectionUtils.isEmpty(audience)) {
			requiredClaims.put(IdTokenClaimNames.AUD, audience);
		}
		Instant expiresAt = idToken.getExpiresAt();
		if (expiresAt == null) {
			requiredClaims.put(IdTokenClaimNames.EXP, expiresAt);
		}
		Instant issuedAt = idToken.getIssuedAt();
		if (issuedAt == null) {
			requiredClaims.put(IdTokenClaimNames.IAT, issuedAt);
		}

		return requiredClaims;
	}
}
