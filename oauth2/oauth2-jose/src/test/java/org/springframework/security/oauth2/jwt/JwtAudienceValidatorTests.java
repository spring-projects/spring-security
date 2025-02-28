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

import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link JwtAudienceValidator}.
 *
 * @author Vedran Pavic
 */
class JwtAudienceValidatorTests {

	private final JwtAudienceValidator validator = new JwtAudienceValidator("audience");

	@Test
	void givenJwtWithMatchingAudienceThenShouldValidate() {
		Jwt jwt = TestJwts.jwt().audience(List.of("audience")).build();
		OAuth2TokenValidatorResult result = this.validator.validate(jwt);
		assertThat(result).isEqualTo(OAuth2TokenValidatorResult.success());
	}

	@Test
	void givenJwtWithoutMatchingAudienceThenShouldValidate() {
		Jwt jwt = TestJwts.jwt().audience(List.of("other")).build();
		OAuth2TokenValidatorResult result = this.validator.validate(jwt);
		assertThat(result.hasErrors()).isTrue();
	}

	@Test
	void givenJwtWithoutAudienceThenShouldValidate() {
		Jwt jwt = TestJwts.jwt().audience(null).build();
		OAuth2TokenValidatorResult result = this.validator.validate(jwt);
		assertThat(result.hasErrors()).isTrue();
	}

}
