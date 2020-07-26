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

import java.util.function.Predicate;

import org.junit.Test;

import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.oauth2.jwt.JwtClaimNames.ISS;
import static org.springframework.security.oauth2.jwt.TestJwts.jwt;

/**
 * Tests for {@link JwtClaimValidator}.
 *
 * @author Zeeshan Adnan
 */
public class JwtClaimValidatorTests {

	private static final Predicate<String> test = claim -> claim.equals("http://test");

	private final JwtClaimValidator<String> validator = new JwtClaimValidator<>(ISS, test);

	@Test
	public void validateWhenClaimPassesTheTestThenReturnsSuccess() {
		Jwt jwt = jwt().claim(ISS, "http://test").build();
		assertThat(this.validator.validate(jwt)).isEqualTo(OAuth2TokenValidatorResult.success());
	}

	@Test
	public void validateWhenClaimFailsTheTestThenReturnsFailure() {
		Jwt jwt = jwt().claim(ISS, "http://abc").build();
		assertThat(this.validator.validate(jwt).getErrors().isEmpty()).isFalse();
	}

	@Test
	public void validateWhenClaimIsNullThenThrowsIllegalArgumentException() {
		assertThatThrownBy(() -> new JwtClaimValidator<String>(null, test))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void validateWhenTestIsNullThenThrowsIllegalArgumentException() {
		assertThatThrownBy(() -> new JwtClaimValidator<>(ISS, null)).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void validateWhenJwtIsNullThenThrowsIllegalArgumentException() {
		assertThatThrownBy(() -> this.validator.validate(null)).isInstanceOf(IllegalArgumentException.class);
	}

}
