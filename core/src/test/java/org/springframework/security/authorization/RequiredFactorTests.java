/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.authorization;

import java.time.Duration;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.authority.FactorGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link RequiredFactor}.
 *
 * @author Rob Winch
 * @since 7.0
 */
class RequiredFactorTests {

	@Test
	void builderWhenNullAuthorityIllegalArgumentException() {
		RequiredFactor.Builder builder = RequiredFactor.builder();
		assertThatIllegalArgumentException().isThrownBy(() -> builder.build());
	}

	@Test
	void withAuthorityThenEquals() {
		RequiredFactor requiredPassword = RequiredFactor.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
			.build();
		assertThat(requiredPassword.getAuthority()).isEqualTo(FactorGrantedAuthority.PASSWORD_AUTHORITY);
		assertThat(requiredPassword.getValidDuration()).isNull();
	}

	@Test
	void builderValidDurationThenEquals() {
		Duration validDuration = Duration.ofMinutes(1);
		RequiredFactor requiredPassword = RequiredFactor.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
			.validDuration(validDuration)
			.build();
		assertThat(requiredPassword.getAuthority()).isEqualTo(FactorGrantedAuthority.PASSWORD_AUTHORITY);
		assertThat(requiredPassword.getValidDuration()).isEqualTo(validDuration);
	}

	@Test
	void builderAuthorizationCodeAuthority() {
		assertBuilderSetsAuthority(RequiredFactor.Builder::authorizationCodeAuthority,
				FactorGrantedAuthority.AUTHORIZATION_CODE_AUTHORITY);
	}

	@Test
	void builderBearerTokenAuthority() {
		assertBuilderSetsAuthority(RequiredFactor.Builder::bearerTokenAuthority,
				FactorGrantedAuthority.BEARER_AUTHORITY);
	}

	@Test
	void builderCasAuthority() {
		assertBuilderSetsAuthority(RequiredFactor.Builder::casAuthority, FactorGrantedAuthority.CAS_AUTHORITY);
	}

	@Test
	void builderPasswordAuthority() {
		assertBuilderSetsAuthority(RequiredFactor.Builder::passwordAuthority,
				FactorGrantedAuthority.PASSWORD_AUTHORITY);
	}

	@Test
	void builderOttAuthority() {
		assertBuilderSetsAuthority(RequiredFactor.Builder::ottAuthority, FactorGrantedAuthority.OTT_AUTHORITY);
	}

	@Test
	void builderSamlAuthority() {
		assertBuilderSetsAuthority(RequiredFactor.Builder::samlAuthority,
				FactorGrantedAuthority.SAML_RESPONSE_AUTHORITY);
	}

	@Test
	void builderWebauthnAuthority() {
		assertBuilderSetsAuthority(RequiredFactor.Builder::webauthnAuthority,
				FactorGrantedAuthority.WEBAUTHN_AUTHORITY);
	}

	@Test
	void builderX509Authority() {
		assertBuilderSetsAuthority(RequiredFactor.Builder::x509Authority, FactorGrantedAuthority.X509_AUTHORITY);
	}

	private static void assertBuilderSetsAuthority(Consumer<RequiredFactor.Builder> configure, String expected) {
		RequiredFactor.Builder builder = RequiredFactor.builder();
		configure.accept(builder);
		RequiredFactor requiredFactor = builder.build();
		assertThat(requiredFactor.getAuthority()).isEqualTo(expected);
	}

}
