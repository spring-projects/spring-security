/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.client.oidc.authentication.logout.LogoutTokenClaimAccessor;
import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/**
 * A {@link OAuth2TokenValidator} that validates OIDC Logout Token claims in conformance
 * with the OIDC Back-Channel Logout Spec.
 *
 * @author Josh Cummings
 * @since 6.2
 * @see OidcLogoutToken
 * @see <a target="_blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken">Logout
 * Token</a>
 * @see <a target="blank" href=
 * "https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation">the OIDC
 * Back-Channel Logout spec</a>
 */
final class OidcBackChannelLogoutTokenValidator implements OAuth2TokenValidator<Jwt> {

	private static final String LOGOUT_VALIDATION_URL = "https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation";

	private static final String BACK_CHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout";

	private final String audience;

	private final String issuer;

	OidcBackChannelLogoutTokenValidator(ClientRegistration clientRegistration) {
		this.audience = clientRegistration.getClientId();
		String issuer = clientRegistration.getProviderDetails().getIssuerUri();
		Assert.hasText(issuer, "Provider issuer cannot be null");
		this.issuer = issuer;
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt jwt) {
		Collection<OAuth2Error> errors = new ArrayList<>();

		LogoutTokenClaimAccessor logoutClaims = jwt::getClaims;
		Map<String, Object> events = logoutClaims.getEvents();
		if (events == null) {
			errors.add(invalidLogoutToken("events claim must not be null"));
		}
		else if (events.get(BACK_CHANNEL_LOGOUT_EVENT) == null) {
			errors.add(invalidLogoutToken("events claim map must contain \"" + BACK_CHANNEL_LOGOUT_EVENT + "\" key"));
		}

		String issuer = logoutClaims.getIssuer().toExternalForm();
		if (issuer == null) {
			errors.add(invalidLogoutToken("iss claim must not be null"));
		}
		else if (!this.issuer.equals(issuer)) {
			errors.add(invalidLogoutToken(
					"iss claim value must match `ClientRegistration#getProviderDetails#getIssuerUri`"));
		}

		List<String> audience = logoutClaims.getAudience();
		if (audience == null) {
			errors.add(invalidLogoutToken("aud claim must not be null"));
		}
		else if (!audience.contains(this.audience)) {
			errors.add(invalidLogoutToken("aud claim value must include `ClientRegistration#getClientId`"));
		}

		Instant issuedAt = logoutClaims.getIssuedAt();
		if (issuedAt == null) {
			errors.add(invalidLogoutToken("iat claim must not be null"));
		}

		String jwtId = logoutClaims.getId();
		if (jwtId == null) {
			errors.add(invalidLogoutToken("jti claim must not be null"));
		}

		if (logoutClaims.getSubject() == null && logoutClaims.getSessionId() == null) {
			errors.add(invalidLogoutToken("sub and sid claims must not both be null"));
		}

		if (logoutClaims.getClaim("nonce") != null) {
			errors.add(invalidLogoutToken("nonce claim must not be present"));
		}

		return OAuth2TokenValidatorResult.failure(errors);
	}

	private static OAuth2Error invalidLogoutToken(String description) {
		return new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, description, LOGOUT_VALIDATION_URL);
	}

}
