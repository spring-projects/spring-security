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
 * An implementation of {@link OAuth2TokenValidator} for verifying claims in a Jwt-based
 * access token
 *
 * <p>
 * Because clocks can differ between the Jwt source, say the Authorization Server, and its
 * destination, say the Resource Server, there is a default clock leeway exercised when
 * deciding if the current time is within the Jwt's specified operating window
 *
 * @author Josh Cummings
 * @since 5.1
 * @see Jwt
 * @see OAuth2TokenValidator
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JSON Web Token
 * (JWT)</a>
 */
public final class JwtTimestampValidator implements OAuth2TokenValidator<Jwt> {

	private final Log logger = LogFactory.getLog(getClass());

	private static final Duration DEFAULT_MAX_CLOCK_SKEW = Duration.of(60, ChronoUnit.SECONDS);

	private final boolean required;

	private final Duration clockSkew;

	private Clock clock = Clock.systemUTC();

	/**
	 * A basic instance with no custom verification and the default max clock skew
	 */
	public JwtTimestampValidator() {
		this(DEFAULT_MAX_CLOCK_SKEW, false);
	}

	public JwtTimestampValidator(boolean required) {
		this(DEFAULT_MAX_CLOCK_SKEW, required);
	}

	public JwtTimestampValidator(Duration clockSkew) {
		this(clockSkew, false);
	}

	public JwtTimestampValidator(Duration clockSkew, boolean required) {
		Assert.notNull(clockSkew, "clockSkew cannot be null");
		this.required = required;
		this.clockSkew = clockSkew;
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt jwt) {
		Assert.notNull(jwt, "jwt cannot be null");
		Instant expiry = jwt.getExpiresAt();
		Instant notBefore = jwt.getNotBefore();
		if (this.required && !(expiry != null || notBefore != null)) {
			OAuth2Error oAuth2Error = createOAuth2Error("exp and nbf are required");
			return OAuth2TokenValidatorResult.failure(oAuth2Error);
		}
		if (expiry != null) {
			if (Instant.now(this.clock).minus(this.clockSkew).isAfter(expiry)) {
				OAuth2Error oAuth2Error = createOAuth2Error(String.format("Jwt expired at %s", jwt.getExpiresAt()));
				return OAuth2TokenValidatorResult.failure(oAuth2Error);
			}
		}
		if (notBefore != null) {
			if (Instant.now(this.clock).plus(this.clockSkew).isBefore(notBefore)) {
				OAuth2Error oAuth2Error = createOAuth2Error(String.format("Jwt used before %s", jwt.getNotBefore()));
				return OAuth2TokenValidatorResult.failure(oAuth2Error);
			}
		}
		return OAuth2TokenValidatorResult.success();
	}

	private OAuth2Error createOAuth2Error(String reason) {
		this.logger.debug(reason);
		return new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, reason,
				"https://tools.ietf.org/html/rfc6750#section-3.1");
	}

	/**
	 * Use this {@link Clock} with {@link Instant#now()} for assessing timestamp validity
	 * @param clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

}
