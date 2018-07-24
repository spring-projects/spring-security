/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.oauth2.jwt;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;

/**
 * @author Josh Cummings
 * @since 5.1
 */
public final class JwtValidators {

	/**
	 * Create a {@link Jwt} Validator that contains all standard validators as well as
	 * any supplied in the parameter list.
	 *
	 * @param jwtValidators - additional validators to include in the delegating validator
	 * @return - a delegating validator containing all standard validators as well as any supplied
	 */
	public static OAuth2TokenValidator<Jwt> createDelegatingJwtValidator(OAuth2TokenValidator<Jwt>... jwtValidators) {
		Collection<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
		validators.add(new JwtTimestampValidator());
		validators.addAll(Arrays.asList(jwtValidators));
		return new DelegatingOAuth2TokenValidator<>(validators);
	}

	private JwtValidators() {}
}
