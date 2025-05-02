/*
 * Copyright 2002-2020 the original author or authors.
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

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.util.Assert;

/**
 * Validates the "iss" claim in a {@link Jwt}, that is matches a configured value
 *
 * @author Josh Cummings
 * @since 5.1
 */
public final class JwtIssuerValidator implements OAuth2TokenValidator<Jwt> {

	private final JwtClaimValidator<Object> validator;

	/**
	 * Constructs a {@link JwtIssuerValidator} using the provided parameters with
	 * {@link JwtClaimNames#ISS "iss"} claim is REQUIRED
	 * @param issuer - The issuer that each {@link Jwt} should have.
	 */
	public JwtIssuerValidator(String issuer) {
		this(issuer, true);
	}

	/**
	 * Constructs a {@link JwtIssuerValidator} using the provided parameters
	 * @param issuer - The issuer that each {@link Jwt} should have.
	 * @param required -{@code true} if the {@link JwtClaimNames#ISS "iss"} claim is
	 * REQUIRED in the {@link Jwt}, {@code false} otherwise
	 */
	public JwtIssuerValidator(String issuer, boolean required) {
		Assert.notNull(issuer, "issuer cannot be null");
		this.validator = new JwtClaimValidator<>(JwtClaimNames.ISS,
				(claimValue) -> (claimValue != null) ? issuer.equals(claimValue.toString()) : !required);
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt token) {
		Assert.notNull(token, "jwt cannot be null");
		return this.validator.validate(token);
	}

}
