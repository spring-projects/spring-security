/*
 * Copyright 2002-2021 the original author or authors.
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
import java.util.Objects;
import java.util.function.Predicate;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link JwtClaimValidator}.
 *
 * @author Zeeshan Adnan
 */
public class JwtClaimValidatorTests {

	private static final Predicate<String> test = (claim) -> claim.equals("http://test");

	private final JwtClaimValidator<String> validator = new JwtClaimValidator<>(JwtClaimNames.ISS, test);

	@Test
	public void validateWhenClaimPassesTheTestThenReturnsSuccess() {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.ISS, "http://test").build();
		assertThat(this.validator.validate(jwt)).isEqualTo(OAuth2TokenValidatorResult.success());
	}

	@Test
	public void validateWhenClaimFailsTheTestThenReturnsFailure() {
		Jwt jwt = TestJwts.jwt().claim(JwtClaimNames.ISS, "http://abc").build();
		Collection<OAuth2Error> details = this.validator.validate(jwt).getErrors();
		assertThat(this.validator.validate(jwt).getErrors().isEmpty()).isFalse();
		assertThat(details).allMatch((error) -> Objects.equals(error.getErrorCode(), OAuth2ErrorCodes.INVALID_TOKEN));
	}

	@Test
	public void validateWhenClaimIsNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new JwtClaimValidator<>(null, test));
	}

	@Test
	public void validateWhenTestIsNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new JwtClaimValidator<>(JwtClaimNames.ISS, null));
	}

	@Test
	public void validateWhenJwtIsNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.validator.validate(null));
	}

}
