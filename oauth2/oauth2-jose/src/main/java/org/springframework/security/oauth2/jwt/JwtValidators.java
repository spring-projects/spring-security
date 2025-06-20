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
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Predicate;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
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
		return new DelegatingOAuth2TokenValidator<>(Arrays.asList(JwtTypeValidator.jwt(), new JwtTimestampValidator(),
				new X509CertificateThumbprintValidator(
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
		JwtTypeValidator typeValidator = CollectionUtils.findValueOfType(tokenValidators, JwtTypeValidator.class);
		if (typeValidator == null) {
			tokenValidators.add(0, JwtTypeValidator.jwt());
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

	/**
	 * Return a {@link AtJwtBuilder} for building a validator that conforms to
	 * <a href="https://datatracker.ietf.org/doc/html/rfc9068">RFC 9068</a>.
	 * @return the {@link AtJwtBuilder} for configuration
	 * @since 6.5
	 */
	public static AtJwtBuilder createAtJwtValidator() {
		return new AtJwtBuilder();
	}

	private static RequireClaimValidator require(String claim) {
		return new RequireClaimValidator(claim);
	}

	/**
	 * A class for building a validator that conforms to
	 * <a href="https://datatracker.ietf.org/doc/html/rfc9068">RFC 9068</a>.
	 *
	 * <p>
	 * To comply with this spec, this builder needs you to specify at least the
	 * {@link #audience}, {@link #issuer}, and {@link #clientId}.
	 *
	 * <p>
	 * While building, the claims are keyed by claim name to allow for simplified lookup
	 * and replacement in {@link #validators}.
	 *
	 * @author Josh Cummings
	 * @since 6.5
	 */
	public static final class AtJwtBuilder {

		Map<String, OAuth2TokenValidator<Jwt>> validators = new LinkedHashMap<>();

		private AtJwtBuilder() {
			JwtTimestampValidator timestamps = new JwtTimestampValidator();
			this.validators.put(JoseHeaderNames.TYP, new JwtTypeValidator(List.of("at+jwt", "application/at+jwt")));
			this.validators.put(JwtClaimNames.EXP, require(JwtClaimNames.EXP).and(timestamps));
			this.validators.put(JwtClaimNames.SUB, require(JwtClaimNames.SUB));
			this.validators.put(JwtClaimNames.IAT, require(JwtClaimNames.IAT).and(timestamps));
			this.validators.put(JwtClaimNames.JTI, require(JwtClaimNames.JTI));
		}

		/**
		 * Validate that each token has this <a href=
		 * "https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1">issuer</a>.
		 * @param issuer the required issuer
		 * @return the {@link AtJwtBuilder} for further configuration
		 */
		public AtJwtBuilder issuer(String issuer) {
			return validators((v) -> v.put(JwtClaimNames.ISS, new JwtIssuerValidator(issuer)));
		}

		/**
		 * Validate that each token has this <a href=
		 * "https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3">audience</a>.
		 * @param audience the required audience
		 * @return the {@link AtJwtBuilder} for further configuration
		 */
		public AtJwtBuilder audience(String audience) {
			return validators((v) -> v.put(JwtClaimNames.AUD, new JwtAudienceValidator(audience)));
		}

		/**
		 * Validate that each token has this <a href=
		 * "https://datatracker.ietf.org/doc/html/rfc8693#name-client_id-client-identifier">client_id</a>.
		 * @param clientId the client identifier to use
		 * @return the {@link AtJwtBuilder} for further configuration
		 */
		public AtJwtBuilder clientId(String clientId) {
			return validators((v) -> v.put("client_id", require("client_id").isEqualTo(clientId)));
		}

		/**
		 * Mutate the list of validators by claim name.
		 *
		 * <p>
		 * For example, to add a validator for
		 * <a href="https://datatracker.ietf.org/doc/html/rfc9068#section-2.2.1">azp</a>
		 * do: <code>
		 * 	builder.validators((v) -> v.put("acr", myValidator()));
		 * </code>
		 *
		 * <p>
		 * A validator is required for all required RFC 9068 claims.
		 * @param validators the mutator for the map of validators
		 * @return the {@link AtJwtBuilder} for further configuration
		 */
		public AtJwtBuilder validators(Consumer<Map<String, OAuth2TokenValidator<Jwt>>> validators) {
			validators.accept(this.validators);
			return this;
		}

		/**
		 * Build the validator
		 * @return the RFC 9068 validator
		 */
		public OAuth2TokenValidator<Jwt> build() {
			List.of(JoseHeaderNames.TYP, JwtClaimNames.EXP, JwtClaimNames.SUB, JwtClaimNames.IAT, JwtClaimNames.JTI,
					JwtClaimNames.ISS, JwtClaimNames.AUD, "client_id")
				.forEach((name) -> Assert.isTrue(this.validators.containsKey(name), name + " must be validated"));
			return new DelegatingOAuth2TokenValidator<>(this.validators.values());
		}

	}

	private static final class RequireClaimValidator implements OAuth2TokenValidator<Jwt> {

		private final String claimName;

		RequireClaimValidator(String claimName) {
			this.claimName = claimName;
		}

		@Override
		public OAuth2TokenValidatorResult validate(Jwt token) {
			if (token.getClaim(this.claimName) == null) {
				return OAuth2TokenValidatorResult
					.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, this.claimName + " must have a value",
							"https://datatracker.ietf.org/doc/html/rfc9068#name-data-structure"));
			}
			return OAuth2TokenValidatorResult.success();
		}

		OAuth2TokenValidator<Jwt> isEqualTo(String value) {
			return and(satisfies((jwt) -> value.equals(jwt.getClaim(this.claimName))));
		}

		OAuth2TokenValidator<Jwt> satisfies(Predicate<Jwt> predicate) {
			return and((jwt) -> {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, this.claimName + " is not valid",
						"https://datatracker.ietf.org/doc/html/rfc9068#name-data-structure");
				if (predicate.test(jwt)) {
					return OAuth2TokenValidatorResult.success();
				}
				return OAuth2TokenValidatorResult.failure(error);
			});
		}

		OAuth2TokenValidator<Jwt> and(OAuth2TokenValidator<Jwt> that) {
			return (jwt) -> {
				OAuth2TokenValidatorResult result = validate(jwt);
				return (result.hasErrors()) ? result : that.validate(jwt);
			};
		}

	}

}
