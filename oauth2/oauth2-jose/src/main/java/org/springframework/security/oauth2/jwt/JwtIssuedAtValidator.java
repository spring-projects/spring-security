/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.oauth2.jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.util.Assert;

/**
 * An {@link OAuth2TokenValidator} responsible for validating the {@link JwtClaimNames#IAT
 * "iat"} claim in the {@link Jwt}.
 *
 * @author Joe Grandja
 * @since 6.5
 * @see OAuth2TokenValidator
 * @see Jwt
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc7519">JSON Web
 * Token (JWT)</a>
 */
public final class JwtIssuedAtValidator implements OAuth2TokenValidator<Jwt> {

	private final boolean required;

	private Duration clockSkew = Duration.ofSeconds(60);

	private Clock clock = Clock.systemUTC();

	/**
	 * Constructs a {@code JwtIssuedAtValidator} with the defaults.
	 */
	public JwtIssuedAtValidator() {
		this(false);
	}

	/**
	 * Constructs a {@code JwtIssuedAtValidator} using the provided parameters.
	 * @param required {@code true} if the {@link JwtClaimNames#IAT "iat"} claim is
	 * REQUIRED in the {@link Jwt}, {@code false} otherwise
	 */
	public JwtIssuedAtValidator(boolean required) {
		this.required = required;
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt jwt) {
		Assert.notNull(jwt, "jwt cannot be null");
		Instant issuedAt = jwt.getIssuedAt();
		if (issuedAt == null && this.required) {
			OAuth2Error error = createOAuth2Error("iat claim is required.");
			return OAuth2TokenValidatorResult.failure(error);
		}

		if (issuedAt != null) {
			// Check time window of validity
			Instant now = Instant.now(this.clock);
			Instant notBefore = now.minus(this.clockSkew);
			Instant notAfter = now.plus(this.clockSkew);
			if (issuedAt.isBefore(notBefore) || issuedAt.isAfter(notAfter)) {
				OAuth2Error error = createOAuth2Error("iat claim is invalid.");
				return OAuth2TokenValidatorResult.failure(error);
			}
		}
		return OAuth2TokenValidatorResult.success();
	}

	/**
	 * Sets the clock skew. The default is 60 seconds.
	 * @param clockSkew the clock skew
	 */
	public void setClockSkew(Duration clockSkew) {
		Assert.notNull(clockSkew, "clockSkew cannot be null");
		Assert.isTrue(clockSkew.getSeconds() >= 0, "clockSkew must be >= 0");
		this.clockSkew = clockSkew;
	}

	/**
	 * Sets the {@link Clock} used in {@link Instant#now(Clock)}.
	 * @param clock the clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

	private static OAuth2Error createOAuth2Error(String reason) {
		return new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, reason, null);
	}

}
