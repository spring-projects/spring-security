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

import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.CollectionUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatException;

/**
 * Tests for {@link JwtValidators}.
 *
 * @author Max Batischev
 */
public class JwtValidatorsTests {

	private static final String ISS_CLAIM = "iss";

	@Test
	public void createWhenJwtIssuerValidatorIsPresentThenCreateDefaultValidatorWithJwtIssuerValidator() {
		OAuth2TokenValidator<Jwt> validator = JwtValidators
			.createDefaultWithValidators(new JwtIssuerValidator(ISS_CLAIM));

		assertThat(containsByType(validator, JwtIssuerValidator.class)).isTrue();
		assertThat(containsByType(validator, JwtTimestampValidator.class)).isTrue();
		assertThat(containsByType(validator, X509CertificateThumbprintValidator.class)).isTrue();
	}

	@Test
	@SuppressWarnings("unchecked")
	public void createWhenJwtTimestampValidatorIsPresentThenCreateDefaultValidatorWithOnlyOneJwtTimestampValidator() {
		OAuth2TokenValidator<Jwt> validator = JwtValidators.createDefaultWithValidators(new JwtTimestampValidator());

		DelegatingOAuth2TokenValidator<Jwt> delegatingOAuth2TokenValidator = (DelegatingOAuth2TokenValidator<Jwt>) validator;
		Collection<OAuth2TokenValidator<Jwt>> tokenValidators = (Collection<OAuth2TokenValidator<Jwt>>) ReflectionTestUtils
			.getField(delegatingOAuth2TokenValidator, "tokenValidators");

		assertThat(containsByType(validator, JwtTimestampValidator.class)).isTrue();
		assertThat(containsByType(validator, X509CertificateThumbprintValidator.class)).isTrue();
		assertThat(Objects.requireNonNull(tokenValidators).size()).isEqualTo(2);
	}

	@Test
	public void createWhenEmptyValidatorsThenThrowsException() {
		assertThatException().isThrownBy(() -> JwtValidators.createDefaultWithValidators(Collections.emptyList()));
	}

	@SuppressWarnings("unchecked")
	private boolean containsByType(OAuth2TokenValidator<Jwt> validator, Class<? extends OAuth2TokenValidator<?>> type) {
		DelegatingOAuth2TokenValidator<Jwt> delegatingOAuth2TokenValidator = (DelegatingOAuth2TokenValidator<Jwt>) validator;
		Collection<OAuth2TokenValidator<Jwt>> tokenValidators = (Collection<OAuth2TokenValidator<Jwt>>) ReflectionTestUtils
			.getField(delegatingOAuth2TokenValidator, "tokenValidators");

		OAuth2TokenValidator<?> tokenValidator = CollectionUtils
			.findValueOfType(Objects.requireNonNull(tokenValidators), type);
		return tokenValidator != null;
	}

}
