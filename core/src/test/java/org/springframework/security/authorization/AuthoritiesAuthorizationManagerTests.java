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

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.function.Supplier;

import org.junit.jupiter.api.Test;

import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link AuthoritiesAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 * @author Khyojae
 */
class AuthoritiesAuthorizationManagerTests {

	@Test
	void setRoleHierarchyWhenNullThenIllegalArgumentException() {
		AuthoritiesAuthorizationManager manager = new AuthoritiesAuthorizationManager();
		assertThatIllegalArgumentException().isThrownBy(() -> manager.setRoleHierarchy(null))
				.withMessage("roleHierarchy cannot be null");
	}

	@Test
	void setRoleHierarchyWhenNotNullThenVerifyRoleHierarchy() {
		AuthoritiesAuthorizationManager manager = new AuthoritiesAuthorizationManager();
		RoleHierarchy roleHierarchy = RoleHierarchyImpl.withDefaultRolePrefix().build();
		manager.setRoleHierarchy(roleHierarchy);
		assertThat(manager).extracting("roleHierarchy").isEqualTo(roleHierarchy);
	}

	@Test
	void getRoleHierarchyWhenNotSetThenDefaultsToNullRoleHierarchy() {
		AuthoritiesAuthorizationManager manager = new AuthoritiesAuthorizationManager();
		assertThat(manager).extracting("roleHierarchy").isInstanceOf(NullRoleHierarchy.class);
	}

	@Test
	void checkWhenUserHasAnyAuthorityThenGrantedDecision() {
		AuthoritiesAuthorizationManager manager = new AuthoritiesAuthorizationManager();
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "USER");
		assertThat(manager.authorize(authentication, Arrays.asList("ADMIN", "USER")).isGranted()).isTrue();
	}

	@Test
	void checkWhenUserHasNotAnyAuthorityThenDeniedDecision() {
		AuthoritiesAuthorizationManager manager = new AuthoritiesAuthorizationManager();
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ANONYMOUS");
		assertThat(manager.authorize(authentication, Arrays.asList("ADMIN", "USER")).isGranted()).isFalse();
	}

	@Test
	void checkWhenRoleHierarchySetThenGreaterRoleTakesPrecedence() {
		AuthoritiesAuthorizationManager manager = new AuthoritiesAuthorizationManager();
		RoleHierarchyImpl roleHierarchy = RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_USER");
		manager.setRoleHierarchy(roleHierarchy);
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password",
				"ROLE_ADMIN");
		assertThat(manager.authorize(authentication, Collections.singleton("ROLE_USER")).isGranted()).isTrue();
	}

	@Test
	void authorizeWhenAuthorityIsNullThenDoesNotThrowNullPointerException() {
		AuthoritiesAuthorizationManager manager = new AuthoritiesAuthorizationManager();

		Authentication authentication = new TestingAuthenticationToken("user", "password",
				Collections.singletonList(() -> null));

		Collection<String> authorities = Collections.singleton("ROLE_USER");

		assertThat(manager.authorize(() -> authentication, authorities).isGranted()).isFalse();
	}
}
