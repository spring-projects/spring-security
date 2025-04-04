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

import java.util.Collection;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.util.Assert;

/**
 * Validates that the "aud" claim in a {@link Jwt} matches a configured value.
 *
 * @author Vedran Pavic
 * @since 6.5
 */
public final class JwtAudienceValidator implements OAuth2TokenValidator<Jwt> {

	private final JwtClaimValidator<Collection<String>> validator;

	/**
	 * Constructs a {@link JwtAudienceValidator} using the provided parameters
	 * @param audience - The audience that each {@link Jwt} should have.
	 */
	public JwtAudienceValidator(String audience) {
		Assert.notNull(audience, "audience cannot be null");
		this.validator = new JwtClaimValidator<>(JwtClaimNames.AUD,
				(claimValue) -> (claimValue != null) && claimValue.contains(audience));
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt token) {
		Assert.notNull(token, "token cannot be null");
		return this.validator.validate(token);
	}

}
