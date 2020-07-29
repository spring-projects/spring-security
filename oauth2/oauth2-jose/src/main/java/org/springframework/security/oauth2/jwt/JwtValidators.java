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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;

/**
 * Provides factory methods for creating {@code OAuth2TokenValidator<Jwt>}
 *
 * @author Josh Cummings
 * @author Rob Winch
 * @since 5.1
 */
public final class JwtValidators {

	/**
	 * <p>
	 * Create a {@link Jwt} Validator that contains all standard validators when an issuer
	 * is known.
	 * </p>
	 * <p>
	 * User's wanting to leverage the defaults plus additional validation can add the
	 * result of this method to {@code DelegatingOAuth2TokenValidator} along with the
	 * additional validators.
	 * </p>
	 * @param issuer the issuer
	 * @return - a delegating validator containing all standard validators as well as any
	 * supplied
	 */
	public static OAuth2TokenValidator<Jwt> createDefaultWithIssuer(String issuer) {
		List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
		validators.add(new JwtTimestampValidator());
		validators.add(new JwtIssuerValidator(issuer));
		return new DelegatingOAuth2TokenValidator<>(validators);
	}

	/**
	 * <p>
	 * Create a {@link Jwt} Validator that contains all standard validators.
	 * </p>
	 * <p>
	 * User's wanting to leverage the defaults plus additional validation can add the
	 * result of this method to {@code DelegatingOAuth2TokenValidator} along with the
	 * additional validators.
	 * </p>
	 * @return - a delegating validator containing all standard validators as well as any
	 * supplied
	 */
	public static OAuth2TokenValidator<Jwt> createDefault() {
		return new DelegatingOAuth2TokenValidator<>(Arrays.asList(new JwtTimestampValidator()));
	}

	private JwtValidators() {
	}

}
