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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A validator for the {@code typ} header. Specifically for indicating the header values
 * that a given {@link JwtDecoder} will support.
 *
 * @author Josh Cummings
 * @since 6.5
 */
public final class JwtTypeValidator implements OAuth2TokenValidator<Jwt> {

	private Collection<String> validTypes;

	private boolean allowEmpty;

	public JwtTypeValidator(Collection<String> validTypes) {
		Assert.notEmpty(validTypes, "validTypes cannot be empty");
		this.validTypes = new ArrayList<>(validTypes);
	}

	/**
	 * Require that the {@code typ} header be {@code JWT} or absent
	 */
	public static JwtTypeValidator jwt() {
		JwtTypeValidator validator = new JwtTypeValidator(List.of("JWT"));
		validator.setAllowEmpty(true);
		return validator;
	}

	/**
	 * Whether to allow the {@code typ} header to be empty. The default value is
	 * {@code false}
	 */
	public void setAllowEmpty(boolean allowEmpty) {
		this.allowEmpty = allowEmpty;
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt token) {
		String typ = (String) token.getHeaders().get(JoseHeaderNames.TYP);
		if (this.allowEmpty && !StringUtils.hasText(typ)) {
			return OAuth2TokenValidatorResult.success();
		}
		if (this.validTypes.contains(typ)) {
			return OAuth2TokenValidatorResult.success();
		}
		return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
				"the given typ value needs to be one of " + this.validTypes,
				"https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.9"));
	}

}
