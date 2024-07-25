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

package org.springframework.security.oauth2.jwt;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.util.Assert;

/**
 * An implementation of {@link OAuth2TokenValidator} for verifying "auth_time" claim in a
 * {@link Jwt}.
 *
 * @author Max Batischev
 * @since 6.4
 * @see Jwt
 * @see OAuth2TokenValidator
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token
 * (JWT)</a>
 */
public final class JwtAuthTimeValidator implements OAuth2TokenValidator<Jwt> {

	private final Log logger = LogFactory.getLog(getClass());

	private final long maxAge;

	private static final Duration DEFAULT_MAX_CLOCK_SKEW = Duration.of(60, ChronoUnit.SECONDS);

	private final Duration clockSkew;

	private Clock clock = Clock.systemUTC();

	public JwtAuthTimeValidator(long maxAge) {
		Assert.isTrue(maxAge > 0, "maxAge must be > 0");
		this.maxAge = maxAge;
		this.clockSkew = DEFAULT_MAX_CLOCK_SKEW;
	}

	public JwtAuthTimeValidator(long maxAge, Duration clockSkew) {
		Assert.isTrue(maxAge > 0, "maxAge must be > 0");
		Assert.notNull(clockSkew, "clockSkew cannot be null");
		this.maxAge = maxAge;
		this.clockSkew = clockSkew;
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt token) {
		Assert.notNull(token, "token cannot be null");
		long authTime = token.getClaim(JwtClaimNames.AUTH_TIME);
		Instant authTimeInstant = Instant.ofEpochSecond(authTime);
		Instant currentInstant = Instant.now(this.clock).minus(this.clockSkew);

		Duration duration = Duration.between(authTimeInstant, currentInstant);
		if (duration.toSeconds() <= this.maxAge) {
			return OAuth2TokenValidatorResult.success();
		}

		return OAuth2TokenValidatorResult.failure(createOAuth2Error());
	}

	private OAuth2Error createOAuth2Error() {
		String reason = String.format("\"More recent authentication is required\", max_age=\"%s\"", this.maxAge);
		this.logger.debug(reason);
		return new OAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_USER_AUTHENTICATION, reason,
				"https://datatracker.ietf.org/doc/html/rfc9470#name-authentication-requirements");
	}

	/**
	 * Use this {@link Clock} with {@link Instant#now()}
	 * @param clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

}
