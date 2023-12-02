/*
 * Copyright 2002-2023 the original author or authors.
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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link AuthorizationManagers}.
 *
 * @author Evgeniy Cheban
 */
class AuthorizationManagersTests {

	@Test
	void checkAnyOfWhenOneGrantedThenGrantedDecision() {
		AuthorizationManager<?> composed = AuthorizationManagers.anyOf((a, o) -> new AuthorizationDecision(false),
				(a, o) -> new AuthorizationDecision(true));
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	void checkAnyOfWithAllAbstainDefaultDecisionWhenOneGrantedThenGrantedDecision() {
		AuthorizationDecision allAbstainDefaultDecision = new AuthorizationDecision(false);
		AuthorizationManager<?> composed = AuthorizationManagers.anyOf(allAbstainDefaultDecision,
				(a, o) -> new AuthorizationDecision(false), (a, o) -> new AuthorizationDecision(true));
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	// gh-13069
	@Test
	void checkAnyOfWhenAllNonAbstainingDeniesThenDeniedDecision() {
		AuthorizationManager<?> composed = AuthorizationManagers.anyOf((a, o) -> new AuthorizationDecision(false),
				(a, o) -> null);
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	void checkAnyOfWhenEmptyThenDeniedDecision() {
		AuthorizationManager<?> composed = AuthorizationManagers.anyOf();
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	void checkAnyOfWithAllAbstainDefaultDecisionIsDeniedWhenEmptyThenDeniedDecision() {
		AuthorizationDecision allAbstainDefaultDecision = new AuthorizationDecision(false);
		AuthorizationManager<?> composed = AuthorizationManagers.anyOf(allAbstainDefaultDecision);
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	void checkAnyOfWithAllAbstainDefaultDecisionIsGrantedWhenEmptyThenGrantedDecision() {
		AuthorizationDecision allAbstainDefaultDecision = new AuthorizationDecision(true);
		AuthorizationManager<?> composed = AuthorizationManagers.anyOf(allAbstainDefaultDecision);
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	void checkAnyOfWithAllAbstainDefaultDecisionIsAbstainWhenEmptyThenAbstainDecision() {
		AuthorizationDecision allAbstainDefaultDecision = null;
		AuthorizationManager<?> composed = AuthorizationManagers.anyOf(allAbstainDefaultDecision);
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNull();
	}

	@Test
	void checkAnyOfWhenAllAbstainDefaultDecisionIsGrantedAndAllManagersAbstainThenGrantedDecision() {
		AuthorizationDecision allAbstainDefaultDecision = new AuthorizationDecision(true);
		AuthorizationManager<?> composed = AuthorizationManagers.anyOf(allAbstainDefaultDecision, (a, o) -> null);
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	void checkAnyOfWhenAllAbstainDefaultDecisionIsDeniedAndAllManagersAbstainThenDeniedDecision() {
		AuthorizationDecision allAbstainDefaultDecision = new AuthorizationDecision(false);
		AuthorizationManager<?> composed = AuthorizationManagers.anyOf(allAbstainDefaultDecision, (a, o) -> null);
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	void checkAnyOfWhenAllAbstainDefaultDecisionIsAbstainAndAllManagersAbstainThenAbstainDecision() {
		AuthorizationDecision allAbstainDefaultDecision = null;
		AuthorizationManager<?> composed = AuthorizationManagers.anyOf(allAbstainDefaultDecision, (a, o) -> null);
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNull();
	}

	@Test
	void checkAllOfWhenAllGrantedThenGrantedDecision() {
		AuthorizationManager<?> composed = AuthorizationManagers.allOf((a, o) -> new AuthorizationDecision(true),
				(a, o) -> new AuthorizationDecision(true));
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	void checkAllOfWithAllAbstainDefaultDecisionWhenAllGrantedThenGrantedDecision() {
		AuthorizationDecision allAbstainDefaultDecision = new AuthorizationDecision(false);
		AuthorizationManager<?> composed = AuthorizationManagers.allOf(allAbstainDefaultDecision,
				(a, o) -> new AuthorizationDecision(true), (a, o) -> new AuthorizationDecision(true));
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	// gh-13069
	@Test
	void checkAllOfWhenAllNonAbstainingGrantsThenGrantedDecision() {
		AuthorizationManager<?> composed = AuthorizationManagers.allOf((a, o) -> new AuthorizationDecision(true),
				(a, o) -> null);
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	void checkAllOfWhenOneDeniedThenDeniedDecision() {
		AuthorizationManager<?> composed = AuthorizationManagers.allOf((a, o) -> new AuthorizationDecision(true),
				(a, o) -> new AuthorizationDecision(false));
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	void checkAllOfWithAllAbstainDefaultDecisionWhenOneDeniedThenDeniedDecision() {
		AuthorizationDecision allAbstainDefaultDecision = new AuthorizationDecision(true);
		AuthorizationManager<?> composed = AuthorizationManagers.allOf(allAbstainDefaultDecision,
				(a, o) -> new AuthorizationDecision(true), (a, o) -> new AuthorizationDecision(false));
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	void checkAllOfWhenEmptyThenGrantedDecision() {
		AuthorizationManager<?> composed = AuthorizationManagers.allOf();
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	void checkAllOfWithAllAbstainDefaultDecisionIsDeniedWhenEmptyThenDeniedDecision() {
		AuthorizationDecision allAbstainDefaultDecision = new AuthorizationDecision(false);
		AuthorizationManager<?> composed = AuthorizationManagers.allOf(allAbstainDefaultDecision);
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	void checkAllOfWithAllAbstainDefaultDecisionIsGrantedWhenEmptyThenGrantedDecision() {
		AuthorizationDecision allAbstainDefaultDecision = new AuthorizationDecision(true);
		AuthorizationManager<?> composed = AuthorizationManagers.allOf(allAbstainDefaultDecision);
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	void checkAllOfWithAllAbstainDefaultDecisionIsAbstainWhenEmptyThenAbstainDecision() {
		AuthorizationDecision allAbstainDefaultDecision = null;
		AuthorizationManager<?> composed = AuthorizationManagers.allOf(allAbstainDefaultDecision);
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNull();
	}

	@Test
	void checkAllOfWhenAllAbstainDefaultDecisionIsDeniedAndAllManagersAbstainThenDeniedDecision() {
		AuthorizationDecision allAbstainDefaultDecision = new AuthorizationDecision(false);
		AuthorizationManager<?> composed = AuthorizationManagers.allOf(allAbstainDefaultDecision, (a, o) -> null);
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

	@Test
	void checkAllOfWhenAllAbstainDefaultDecisionIsGrantedAndAllManagersAbstainThenGrantedDecision() {
		AuthorizationDecision allAbstainDefaultDecision = new AuthorizationDecision(true);
		AuthorizationManager<?> composed = AuthorizationManagers.allOf(allAbstainDefaultDecision, (a, o) -> null);
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	void checkAllOfWhenAllAbstainDefaultDecisionIsAbstainAndAllManagersAbstainThenAbstainDecision() {
		AuthorizationDecision allAbstainDefaultDecision = null;
		AuthorizationManager<?> composed = AuthorizationManagers.allOf(allAbstainDefaultDecision, (a, o) -> null);
		AuthorizationDecision decision = composed.check(null, null);
		assertThat(decision).isNull();
	}

	@Test
	void checkNotWhenEmptyThenAbstainedDecision() {
		AuthorizationManager<?> negated = AuthorizationManagers.not((a, o) -> null);
		AuthorizationDecision decision = negated.check(null, null);
		assertThat(decision).isNull();
	}

	@Test
	void checkNotWhenGrantedThenDeniedDecision() {
		AuthorizationManager<?> negated = AuthorizationManagers.not((a, o) -> new AuthorizationDecision(true));
		AuthorizationDecision decision = negated.check(null, null);
		assertThat(decision).isNotNull();
		assertThat(decision.isGranted()).isFalse();
	}

}
