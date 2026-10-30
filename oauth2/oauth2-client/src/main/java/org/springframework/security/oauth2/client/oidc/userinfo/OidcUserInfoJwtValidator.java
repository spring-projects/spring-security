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

package org.springframework.security.oauth2.client.oidc.userinfo;

import java.util.List;

import org.jspecify.annotations.Nullable;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * An {@link OAuth2TokenValidator} that validates the claims of a signed UserInfo Response
 * specific to OpenID Connect 1.0: if the {@code iss} and {@code aud} claims are present,
 * as they should be, they have to identify the Provider and this client.
 *
 * @author Sharang Gupta
 * @since 7.2
 * @see <a href=
 * "https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">OpenID Connect
 * Core 1.0, Successful UserInfo Response</a>
 */
final class OidcUserInfoJwtValidator implements OAuth2TokenValidator<Jwt> {

	private static final String USER_INFO_RESPONSE_URI = "https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse";

	private final @Nullable String issuer;

	private final String clientId;

	OidcUserInfoJwtValidator(ClientRegistration clientRegistration) {
		this.issuer = clientRegistration.getProviderDetails().getIssuerUri();
		this.clientId = clientRegistration.getClientId();
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt jwt) {
		Object issuerClaim = jwt.getClaim(IdTokenClaimNames.ISS);
		if (this.issuer != null && issuerClaim != null && !this.issuer.equals(issuerClaim.toString())) {
			return failure("The iss claim is not valid");
		}
		List<String> audience = jwt.getAudience();
		if (audience != null && !audience.contains(this.clientId)) {
			return failure("The aud claim is not valid");
		}
		return OAuth2TokenValidatorResult.success();
	}

	private static OAuth2TokenValidatorResult failure(String description) {
		return OAuth2TokenValidatorResult
			.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, description, USER_INFO_RESPONSE_URI));
	}

}
