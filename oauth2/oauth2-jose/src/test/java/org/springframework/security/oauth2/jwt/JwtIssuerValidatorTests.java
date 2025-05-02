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

import java.net.MalformedURLException;
import java.net.URL;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Josh Cummings
 * @since 5.1
 */
public class JwtIssuerValidatorTests {

	private static final String ISSUER = "https://issuer";

	private final JwtIssuerValidator validatorDefault = new JwtIssuerValidator(ISSUER);

	private final JwtIssuerValidator validatorRequiredTrue = new JwtIssuerValidator(ISSUER, true);

	private final JwtIssuerValidator validatorRequiredFalse = new JwtIssuerValidator(ISSUER, false);

	@Test
	public void validateWhenRequiredDefaultAndIssuerMatchesThenReturnsSuccess() {
		Jwt jwt = TestJwts.jwt().claim("iss", ISSUER).build();
		// @formatter:off
		assertThat(this.validatorDefault.validate(jwt))
				.isEqualTo(OAuth2TokenValidatorResult.success());
		// @formatter:on
	}

	@Test
	public void validateWhenRequiredAndIssuerMatchesThenReturnsSuccess() {
		Jwt jwt = TestJwts.jwt().claim("iss", ISSUER).build();
		// @formatter:off
		assertThat(this.validatorRequiredTrue.validate(jwt))
				.isEqualTo(OAuth2TokenValidatorResult.success());
		// @formatter:on
	}

	@Test
	public void validateWhenNotRequiredAndIssuerMatchesThenReturnsSuccess() {
		Jwt jwt = TestJwts.jwt().claim("iss", ISSUER).build();
		// @formatter:off
		assertThat(this.validatorRequiredFalse.validate(jwt))
				.isEqualTo(OAuth2TokenValidatorResult.success());
		// @formatter:on
	}

	@Test
	public void validateWhenRequiredDefaultAndIssuerUrlMatchesThenReturnsSuccess() throws MalformedURLException {
		Jwt jwt = TestJwts.jwt().claim("iss", new URL(ISSUER)).build();

		assertThat(this.validatorDefault.validate(jwt)).isEqualTo(OAuth2TokenValidatorResult.success());
	}

	@Test
	public void validateWhenRequiredAndIssuerUrlMatchesThenReturnsSuccess() throws MalformedURLException {
		Jwt jwt = TestJwts.jwt().claim("iss", new URL(ISSUER)).build();

		assertThat(this.validatorRequiredTrue.validate(jwt)).isEqualTo(OAuth2TokenValidatorResult.success());
	}

	@Test
	public void validateWhenNotRequiredAndIssuerUrlMatchesThenReturnsSuccess() throws MalformedURLException {
		Jwt jwt = TestJwts.jwt().claim("iss", new URL(ISSUER)).build();

		assertThat(this.validatorRequiredFalse.validate(jwt)).isEqualTo(OAuth2TokenValidatorResult.success());
	}

	@Test
	public void validateWhenRequiredDefaultAndIssuerMismatchesThenReturnsError() {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.ISS, "https://other").build();
		OAuth2TokenValidatorResult result = this.validatorDefault.validate(jwt);
		assertThat(result.getErrors()).isNotEmpty();
	}

	@Test
	public void validateWhenRequiredAndIssuerMismatchesThenReturnsError() {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.ISS, "https://other").build();
		OAuth2TokenValidatorResult result = this.validatorRequiredTrue.validate(jwt);
		assertThat(result.getErrors()).isNotEmpty();
	}

	@Test
	public void validateWhenNotRequiredAndIssuerMismatchesThenReturnsError() {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.ISS, "https://other").build();
		OAuth2TokenValidatorResult result = this.validatorRequiredFalse.validate(jwt);
		assertThat(result.getErrors()).isNotEmpty();
	}

	@Test
	public void validateWhenRequiredDefaultAndIssuerUrlMismatchesThenReturnsError() throws MalformedURLException {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.ISS, new URL("https://other")).build();

		OAuth2TokenValidatorResult result = this.validatorDefault.validate(jwt);

		assertThat(result.getErrors()).isNotEmpty();
	}

	@Test
	public void validateWhenRequiredAndIssuerUrlMismatchesThenReturnsError() throws MalformedURLException {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.ISS, new URL("https://other")).build();

		OAuth2TokenValidatorResult result = this.validatorRequiredTrue.validate(jwt);

		assertThat(result.getErrors()).isNotEmpty();
	}

	@Test
	public void validateWhenNotRequiredAndIssuerUrlMismatchesThenReturnsError() throws MalformedURLException {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.ISS, new URL("https://other")).build();

		OAuth2TokenValidatorResult result = this.validatorRequiredFalse.validate(jwt);

		assertThat(result.getErrors()).isNotEmpty();
	}

	@Test
	public void validateWhenRequiredDefaultAndJwtHasNoIssuerThenReturnsError() {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.AUD, "https://aud").build();
		OAuth2TokenValidatorResult result = this.validatorDefault.validate(jwt);
		assertThat(result.getErrors()).isNotEmpty();
	}

	@Test
	public void validateWhenRequiredAndJwtHasNoIssuerThenReturnsError() {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.AUD, "https://aud").build();
		OAuth2TokenValidatorResult result = this.validatorRequiredTrue.validate(jwt);
		assertThat(result.getErrors()).isNotEmpty();
	}

	@Test
	public void validateWhenNotRequiredAndJwtHasNoIssuerThenReturnsError() {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.AUD, "https://aud").build();
		OAuth2TokenValidatorResult result = this.validatorRequiredFalse.validate(jwt);
		assertThat(result.getErrors()).isNotEmpty();
	}

	// gh-6073
	@Test
	public void validateWhenRequiredDefaultAndIssuerMatchesAndIsNotAUriThenReturnsSuccess() {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.ISS, "issuer").build();
		JwtIssuerValidator validator = new JwtIssuerValidator("issuer");
		// @formatter:off
		assertThat(validator.validate(jwt))
				.isEqualTo(OAuth2TokenValidatorResult.success());
		// @formatter:on
	}

	// gh-6073
	@Test
	public void validateWhenRequiredAndIssuerMatchesAndIsNotAUriThenReturnsSuccess() {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.ISS, "issuer").build();
		JwtIssuerValidator validator = new JwtIssuerValidator("issuer", true);
		// @formatter:off
		assertThat(validator.validate(jwt))
				.isEqualTo(OAuth2TokenValidatorResult.success());
		// @formatter:on
	}

	// gh-6073
	@Test
	public void validateWhenNotRequiredAndIssuerMatchesAndIsNotAUriThenReturnsSuccess() {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.ISS, "issuer").build();
		JwtIssuerValidator validator = new JwtIssuerValidator("issuer", false);
		// @formatter:off
		assertThat(validator.validate(jwt))
				.isEqualTo(OAuth2TokenValidatorResult.success());
		// @formatter:on
	}

	@Test
	public void validateWhenRequiredDefaultAndJwtIsNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.validatorDefault.validate(null));
		// @formatter:on
	}

	@Test
	public void validateWhenRequiredAndJwtIsNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.validatorRequiredTrue.validate(null));
		// @formatter:on
	}

	@Test
	public void validateWhenNotRequiredAndJwtIsNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.validatorRequiredFalse.validate(null));
		// @formatter:on
	}

	@Test
	public void constructorWhenRequiredDefaultAndNullIssuerIsGivenThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JwtIssuerValidator(null));
		// @formatter:on
	}

	@Test
	public void constructorWhenRequiredAndNullIssuerIsGivenThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JwtIssuerValidator(null, true));
		// @formatter:on
	}

	@Test
	public void constructorWhenNotRequiredAndNullIssuerIsGivenThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new JwtIssuerValidator(null, false));
		// @formatter:on
	}

}
