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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * Provides factory methods for creating {@code OAuth2TokenValidator<Jwt>}
 *
 * @author Josh Cummings
 * @author Rob Winch
 * @since 5.1
 */
public final class JwtValidators {

	private JwtValidators() {
	}

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
		return createDefaultWithValidators(new JwtIssuerValidator(issuer));
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
		return new DelegatingOAuth2TokenValidator<>(
				Arrays.asList(new JwtTimestampValidator(), new X509CertificateThumbprintValidator(
						X509CertificateThumbprintValidator.DEFAULT_X509_CERTIFICATE_SUPPLIER)));
	}

	/**
	 * <p>
	 * Create a {@link Jwt} default validator with standard validators and additional
	 * validators.
	 * </p>
	 * @param validators additional validators
	 * @return - a delegating validator containing all standard validators with additional
	 * validators
	 * @since 6.3
	 */
	public static OAuth2TokenValidator<Jwt> createDefaultWithValidators(List<OAuth2TokenValidator<Jwt>> validators) {
		Assert.notEmpty(validators, "validators cannot be null or empty");
		List<OAuth2TokenValidator<Jwt>> tokenValidators = new ArrayList<>(validators);
		X509CertificateThumbprintValidator x509CertificateThumbprintValidator = CollectionUtils
			.findValueOfType(tokenValidators, X509CertificateThumbprintValidator.class);
		if (x509CertificateThumbprintValidator == null) {
			tokenValidators.add(0, new X509CertificateThumbprintValidator(
					X509CertificateThumbprintValidator.DEFAULT_X509_CERTIFICATE_SUPPLIER));
		}
		JwtTimestampValidator jwtTimestampValidator = CollectionUtils.findValueOfType(tokenValidators,
				JwtTimestampValidator.class);
		if (jwtTimestampValidator == null) {
			tokenValidators.add(0, new JwtTimestampValidator());
		}
		return new DelegatingOAuth2TokenValidator<>(tokenValidators);
	}

	/**
	 * <p>
	 * Create a {@link Jwt} default validator with standard validators and additional
	 * validators.
	 * </p>
	 * @param validators additional validators
	 * @return - a delegating validator containing all standard validators with additional
	 * validators
	 * @since 6.3
	 */
	public static OAuth2TokenValidator<Jwt> createDefaultWithValidators(OAuth2TokenValidator<Jwt>... validators) {
		Assert.notEmpty(validators, "validators cannot be null or empty");
		List<OAuth2TokenValidator<Jwt>> tokenValidators = new ArrayList<>(Arrays.asList(validators));
		return createDefaultWithValidators(tokenValidators);
	}

}
