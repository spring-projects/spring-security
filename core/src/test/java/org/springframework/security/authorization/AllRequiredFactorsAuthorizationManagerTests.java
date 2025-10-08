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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.function.Consumer;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Test {@link AllRequiredFactorsAuthorizationManager}.
 *
 * @author Rob Winch
 * @since 7.0
 */
class AllRequiredFactorsAuthorizationManagerTests {

	private static final Object DOES_NOT_MATTER = new Object();

	private static RequiredFactor REQUIRED_PASSWORD = RequiredFactor
		.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
		.build();

	private static RequiredFactor EXPIRING_PASSWORD = RequiredFactor
		.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
		.validDuration(Duration.ofHours(1))
		.build();

	@Test
	void authorizeWhenGranted() {
		AllRequiredFactorsAuthorizationManager<Object> allFactors = AllRequiredFactorsAuthorizationManager.builder()
			.requireFactor(REQUIRED_PASSWORD)
			.build();
		FactorGrantedAuthority passwordFactor = FactorGrantedAuthority.withAuthority(REQUIRED_PASSWORD.getAuthority())
			.issuedAt(Instant.now())
			.build();
		Authentication authentication = new TestingAuthenticationToken("user", "password", passwordFactor);
		FactorAuthorizationDecision result = allFactors.authorize(() -> authentication, DOES_NOT_MATTER);
		assertThat(result.isGranted()).isTrue();
	}

	@Test
	void authorizeWhenConsumerGranted() {
		AllRequiredFactorsAuthorizationManager<Object> allFactors = AllRequiredFactorsAuthorizationManager.builder()
			.requireFactor((required) -> required.authority(FactorGrantedAuthority.PASSWORD_AUTHORITY))
			.build();
		FactorGrantedAuthority passwordFactor = FactorGrantedAuthority
			.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
			.issuedAt(Instant.now())
			.build();
		Authentication authentication = new TestingAuthenticationToken("user", "password", passwordFactor);
		FactorAuthorizationDecision result = allFactors.authorize(() -> authentication, DOES_NOT_MATTER);
		assertThat(result.isGranted()).isTrue();
	}

	@Test
	void authorizeWhenUnauthenticated() {
		AllRequiredFactorsAuthorizationManager<Object> allFactors = AllRequiredFactorsAuthorizationManager.builder()
			.requireFactor(REQUIRED_PASSWORD)
			.build();
		FactorGrantedAuthority passwordFactor = FactorGrantedAuthority.withAuthority(REQUIRED_PASSWORD.getAuthority())
			.issuedAt(Instant.now())
			.build();
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password", passwordFactor);
		authentication.setAuthenticated(false);
		FactorAuthorizationDecision result = allFactors.authorize(() -> authentication, DOES_NOT_MATTER);
		assertThat(result.isGranted()).isFalse();
		assertThat(result.getFactorErrors()).containsExactly(RequiredFactorError.createMissing(REQUIRED_PASSWORD));
	}

	@Test
	void authorizeWhenNullAuthentication() {
		AllRequiredFactorsAuthorizationManager<Object> allFactors = AllRequiredFactorsAuthorizationManager.builder()
			.requireFactor(EXPIRING_PASSWORD)
			.build();
		Authentication authentication = null;
		FactorAuthorizationDecision result = allFactors.authorize(() -> authentication, DOES_NOT_MATTER);
		assertThat(result.isGranted()).isFalse();
		assertThat(result.getFactorErrors()).containsExactly(RequiredFactorError.createMissing(EXPIRING_PASSWORD));
	}

	@Test
	void authorizeWhenRequiredFactorHasNullDurationThenNullIssuedAtGranted() {
		AllRequiredFactorsAuthorizationManager<Object> allFactors = AllRequiredFactorsAuthorizationManager.builder()
			.requireFactor(REQUIRED_PASSWORD)
			.build();
		FactorGrantedAuthority passwordFactor = FactorGrantedAuthority.withAuthority(REQUIRED_PASSWORD.getAuthority())
			.build();
		Authentication authentication = new TestingAuthenticationToken("user", "password", passwordFactor);
		FactorAuthorizationDecision result = allFactors.authorize(() -> authentication, DOES_NOT_MATTER);
		assertThat(result.isGranted()).isTrue();
	}

	@Test
	void authorizeWhenRequiredFactorHasDurationAndNotFactorGrantedAuthorityThenExpired() {
		AllRequiredFactorsAuthorizationManager<Object> allFactors = AllRequiredFactorsAuthorizationManager.builder()
			.requireFactor(EXPIRING_PASSWORD)
			.build();
		Authentication authentication = new TestingAuthenticationToken("user", "password",
				EXPIRING_PASSWORD.getAuthority());
		FactorAuthorizationDecision result = allFactors.authorize(() -> authentication, DOES_NOT_MATTER);
		assertThat(result.isGranted()).isFalse();
		assertThat(result.getFactorErrors()).containsExactly(RequiredFactorError.createExpired(EXPIRING_PASSWORD));
	}

	@Test
	void authorizeWhenFactorAuthorityMissingThenMissing() {
		AllRequiredFactorsAuthorizationManager<Object> allFactors = AllRequiredFactorsAuthorizationManager.builder()
			.requireFactor(REQUIRED_PASSWORD)
			.build();
		Authentication authentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");
		FactorAuthorizationDecision result = allFactors.authorize(() -> authentication, DOES_NOT_MATTER);
		assertThat(result.isGranted()).isFalse();
		assertThat(result.getFactorErrors()).containsExactly(RequiredFactorError.createMissing(REQUIRED_PASSWORD));
	}

	@Test
	void authorizeWhenGrantedAuthorityThenGranted() {
		AllRequiredFactorsAuthorizationManager<Object> allFactors = AllRequiredFactorsAuthorizationManager.builder()
			.requireFactor(REQUIRED_PASSWORD)
			.build();
		Authentication authentication = new TestingAuthenticationToken("user", "password",
				REQUIRED_PASSWORD.getAuthority());
		FactorAuthorizationDecision result = allFactors.authorize(() -> authentication, DOES_NOT_MATTER);
		assertThat(result.isGranted()).isTrue();
	}

	@Test
	void authorizeWhenExpired() {
		AllRequiredFactorsAuthorizationManager<Object> allFactors = AllRequiredFactorsAuthorizationManager.builder()
			.requireFactor(EXPIRING_PASSWORD)
			.build();
		FactorGrantedAuthority passwordFactor = FactorGrantedAuthority.withAuthority(EXPIRING_PASSWORD.getAuthority())
			.issuedAt(Instant.now().minus(Duration.ofHours(2)))
			.build();
		Authentication authentication = new TestingAuthenticationToken("user", "password", passwordFactor);
		FactorAuthorizationDecision result = allFactors.authorize(() -> authentication, DOES_NOT_MATTER);
		assertThat(result.isGranted()).isFalse();
		assertThat(result.getFactorErrors()).containsExactly(RequiredFactorError.createExpired(EXPIRING_PASSWORD));
	}

	@Test
	void authorizeWhenJustExpired() {
		Instant now = Instant.now();
		Duration expiresIn = Duration.ofHours(1);
		Instant justExpired = now.minus(expiresIn);
		Clock clock = Clock.fixed(now, ZoneId.systemDefault());
		RequiredFactor expiringPassword = RequiredFactor.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
			.validDuration(expiresIn)
			.build();
		AllRequiredFactorsAuthorizationManager<Object> allFactors = AllRequiredFactorsAuthorizationManager.builder()
			.requireFactor(expiringPassword)
			.build();
		allFactors.setClock(clock);
		FactorGrantedAuthority passwordFactor = FactorGrantedAuthority.withAuthority(expiringPassword.getAuthority())
			.issuedAt(justExpired)
			.build();
		Authentication authentication = new TestingAuthenticationToken("user", "password", passwordFactor);
		FactorAuthorizationDecision result = allFactors.authorize(() -> authentication, DOES_NOT_MATTER);
		assertThat(result.isGranted()).isFalse();
		assertThat(result.getFactorErrors()).containsExactly(RequiredFactorError.createExpired(expiringPassword));
	}

	@Test
	void authorizeWhenAlmostExpired() {
		Instant now = Instant.now();
		Duration expiresIn = Duration.ofHours(1);
		Instant justExpired = now.minus(expiresIn).plus(Duration.ofNanos(1));
		Clock clock = Clock.fixed(now, ZoneId.systemDefault());
		RequiredFactor expiringPassword = RequiredFactor.withAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY)
			.validDuration(expiresIn)
			.build();
		AllRequiredFactorsAuthorizationManager<Object> allFactors = AllRequiredFactorsAuthorizationManager.builder()
			.requireFactor(expiringPassword)
			.build();
		allFactors.setClock(clock);
		FactorGrantedAuthority passwordFactor = FactorGrantedAuthority.withAuthority(expiringPassword.getAuthority())
			.issuedAt(justExpired)
			.build();
		Authentication authentication = new TestingAuthenticationToken("user", "password", passwordFactor);
		FactorAuthorizationDecision result = allFactors.authorize(() -> authentication, DOES_NOT_MATTER);
		assertThat(result.isGranted()).isTrue();
	}

	@Test
	void authorizeWhenDifferentFactorGrantedAuthorityThenMissing() {
		AllRequiredFactorsAuthorizationManager<Object> allFactors = AllRequiredFactorsAuthorizationManager.builder()
			.requireFactor(REQUIRED_PASSWORD)
			.build();
		Authentication authentication = new TestingAuthenticationToken("user", "password",
				FactorGrantedAuthority.fromAuthority(REQUIRED_PASSWORD.getAuthority()) + "DIFFERENT");
		FactorAuthorizationDecision result = allFactors.authorize(() -> authentication, DOES_NOT_MATTER);
		assertThat(result.isGranted()).isFalse();
		assertThat(result.getFactorErrors()).containsExactly(RequiredFactorError.createMissing(REQUIRED_PASSWORD));
	}

	@Test
	void setClockWhenNullThenIllegalArgumentException() {
		AllRequiredFactorsAuthorizationManager<Object> allFactors = AllRequiredFactorsAuthorizationManager.builder()
			.requireFactor(REQUIRED_PASSWORD)
			.build();
		assertThatIllegalArgumentException().isThrownBy(() -> allFactors.setClock(null));
	}

	@Test
	void builderBuildWhenEmpty() {
		assertThatIllegalArgumentException().isThrownBy(() -> AllRequiredFactorsAuthorizationManager.builder().build());
	}

	@Test
	void builderWhenNullRequiredFactor() {
		AllRequiredFactorsAuthorizationManager.Builder builder = AllRequiredFactorsAuthorizationManager.builder();
		assertThatIllegalArgumentException().isThrownBy(() -> builder.requireFactor((RequiredFactor) null));
	}

	@Test
	void builderWhenNullConsumerRequiredFactorBuilder() {
		AllRequiredFactorsAuthorizationManager.Builder builder = AllRequiredFactorsAuthorizationManager.builder();
		assertThatIllegalArgumentException()
			.isThrownBy(() -> builder.requireFactor((Consumer<RequiredFactor.Builder>) null));
	}

}
