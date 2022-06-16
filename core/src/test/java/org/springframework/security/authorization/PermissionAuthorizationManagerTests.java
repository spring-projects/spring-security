/*
 * Copyright 2002-2022 the original author or authors.
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

import java.io.Serializable;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.DenyAllPermissionEvaluator;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link PermissionAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 */
class PermissionAuthorizationManagerTests {

	@Test
	void instantiateWhenPermissionNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new PermissionAuthorizationManager<>(null))
				.withMessage("permission cannot be empty");
	}

	@Test
	void setPermissionEvaluatorWhenNullThenException() {
		PermissionAuthorizationManager<Object> manager = new PermissionAuthorizationManager<>("read");
		assertThatIllegalArgumentException().isThrownBy(() -> manager.setPermissionEvaluator(null))
				.withMessage("permissionEvaluator cannot be null");
	}

	@Test
	void setPermissionEvaluatorWhenNotNullThenVerifyPermissionEvaluator() {
		PermissionAuthorizationManager<Object> manager = new PermissionAuthorizationManager<>("read");
		PermissionEvaluator permissionEvaluator = new DenyAllPermissionEvaluator();
		manager.setPermissionEvaluator(permissionEvaluator);
		assertThat(manager).extracting("permissionEvaluator").isEqualTo(permissionEvaluator);
	}

	@Test
	void whenPermissionEvaluatorNotSetThenDefaultsToDenyAllPermissionEvaluator() {
		PermissionAuthorizationManager<Object> manager = new PermissionAuthorizationManager<>("read");
		assertThat(manager).extracting("permissionEvaluator").isInstanceOf(DenyAllPermissionEvaluator.class);
	}

	@Test
	void checkWhenUserHasPermissionThenGrantedDecision() {
		PermissionAuthorizationManager<Object> manager = new PermissionAuthorizationManager<>("read");
		manager.setPermissionEvaluator(new TestPermissionEvaluator());
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("read", "password");
		Object object = new Object();
		AuthorizationDecision decision = manager.check(authentication, object);
		assertThat(decision.isGranted()).isTrue();
	}

	@Test
	void checkWhenUserHasNotPermissionThenDeniedDecision() {
		PermissionAuthorizationManager<Object> manager = new PermissionAuthorizationManager<>("read");
		manager.setPermissionEvaluator(new TestPermissionEvaluator());
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password");
		Object object = new Object();
		AuthorizationDecision decision = manager.check(authentication, object);
		assertThat(decision.isGranted()).isFalse();
	}

	private static final class TestPermissionEvaluator implements PermissionEvaluator {

		@Override
		public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
			return authentication.getName().equals(permission);
		}

		@Override
		public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
				Object permission) {
			return authentication.getName().equals(permission);
		}

	}

}
