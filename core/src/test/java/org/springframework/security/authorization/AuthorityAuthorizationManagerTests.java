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

package org.springframework.security.authorization;

import java.util.function.Supplier;

import org.junit.Test;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link AuthorityAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 */
public class AuthorityAuthorizationManagerTests {

	@Test
	public void hasRoleWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> AuthorityAuthorizationManager.hasRole(null))
				.withMessage("role cannot be null");
	}

	@Test
	public void hasAuthorityWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> AuthorityAuthorizationManager.hasAuthority(null))
				.withMessage("authority cannot be null");
	}

	@Test
	public void hasAnyRoleWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> AuthorityAuthorizationManager.hasAnyRole(null))
				.withMessage("roles cannot be empty");
	}

	@Test
	public void hasAnyRoleWhenEmptyThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> AuthorityAuthorizationManager.hasAnyRole(new String[] {}))
				.withMessage("roles cannot be empty");
	}

	@Test
	public void hasAnyRoleWhenContainNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> AuthorityAuthorizationManager.hasAnyRole("ADMIN", null, "USER"))
				.withMessage("roles cannot contain null values");
	}

	@Test
	public void hasAnyRoleWhenCustomRolePrefixNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> AuthorityAuthorizationManager.hasAnyRole(null, new String[] { "ADMIN", "USER" }))
				.withMessage("rolePrefix cannot be null");
	}

	@Test
	public void hasAnyAuthorityWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> AuthorityAuthorizationManager.hasAnyAuthority(null))
				.withMessage("authorities cannot be empty");
	}

	@Test
	public void hasAnyAuthorityWhenEmptyThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> AuthorityAuthorizationManager.hasAnyAuthority(new String[] {}))
				.withMessage("authorities cannot be empty");
	}

	@Test
	public void hasAnyAuthorityWhenContainNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> AuthorityAuthorizationManager.hasAnyAuthority("ADMIN", null, "USER"))
				.withMessage("authorities cannot contain null values");
	}

	@Test
	public void hasRoleWhenUserHasRoleThenGrantedDecision() {
		AuthorityAuthorizationManager<Object> manager = AuthorityAuthorizationManager.hasRole("ADMIN");

		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_ADMIN",
				"ROLE_USER");
		Object object = new Object();

		assertThat(manager.check(authentication, object).isGranted()).isTrue();
	}

	@Test
	public void hasRoleWhenUserHasNotRoleThenDeniedDecision() {
		AuthorityAuthorizationManager<Object> manager = AuthorityAuthorizationManager.hasRole("ADMIN");

		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		Object object = new Object();

		assertThat(manager.check(authentication, object).isGranted()).isFalse();
	}

	@Test
	public void hasAuthorityWhenUserHasAuthorityThenGrantedDecision() {
		AuthorityAuthorizationManager<Object> manager = AuthorityAuthorizationManager.hasAuthority("ADMIN");

		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ADMIN",
				"USER");
		Object object = new Object();

		assertThat(manager.check(authentication, object).isGranted()).isTrue();
	}

	@Test
	public void hasAuthorityWhenUserHasNotAuthorityThenDeniedDecision() {
		AuthorityAuthorizationManager<Object> manager = AuthorityAuthorizationManager.hasAuthority("ADMIN");

		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "USER");
		Object object = new Object();

		assertThat(manager.check(authentication, object).isGranted()).isFalse();
	}

	@Test
	public void hasAnyRoleWhenUserHasAnyRoleThenGrantedDecision() {
		AuthorityAuthorizationManager<Object> manager = AuthorityAuthorizationManager.hasAnyRole("ADMIN", "USER");

		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ROLE_USER");
		Object object = new Object();

		assertThat(manager.check(authentication, object).isGranted()).isTrue();
	}

	@Test
	public void hasAnyRoleWhenUserHasNotAnyRoleThenDeniedDecision() {
		AuthorityAuthorizationManager<Object> manager = AuthorityAuthorizationManager.hasAnyRole("ADMIN", "USER");

		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password",
				"ROLE_ANONYMOUS");
		Object object = new Object();

		assertThat(manager.check(authentication, object).isGranted()).isFalse();
	}

	@Test
	public void hasAnyRoleWhenCustomRolePrefixProvidedThenUseCustomRolePrefix() {
		AuthorityAuthorizationManager<Object> manager = AuthorityAuthorizationManager.hasAnyRole("CUSTOM_",
				new String[] { "USER" });
		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password",
				"CUSTOM_USER");
		Object object = new Object();

		assertThat(manager.check(authentication, object).isGranted()).isTrue();
	}

	@Test
	public void hasAnyAuthorityWhenUserHasAnyAuthorityThenGrantedDecision() {
		AuthorityAuthorizationManager<Object> manager = AuthorityAuthorizationManager.hasAnyAuthority("ADMIN", "USER");

		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "USER");
		Object object = new Object();

		assertThat(manager.check(authentication, object).isGranted()).isTrue();
	}

	@Test
	public void hasAnyAuthorityWhenUserHasNotAnyAuthorityThenDeniedDecision() {
		AuthorityAuthorizationManager<Object> manager = AuthorityAuthorizationManager.hasAnyAuthority("ADMIN", "USER");

		Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password", "ANONYMOUS");
		Object object = new Object();

		assertThat(manager.check(authentication, object).isGranted()).isFalse();
	}

}
