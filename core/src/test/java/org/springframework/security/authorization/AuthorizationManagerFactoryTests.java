/*
 * Copyright 2002-present the original author or authors.
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
 * Tests for {@link AuthorizationManagerFactory}.
 *
 * @author Steve Riesenberg
 */
public class AuthorizationManagerFactoryTests {

	@Test
	public void permitAllReturnsSingleResultAuthorizationManagerByDefault() {
		AuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		AuthorizationManager<String> authorizationManager = factory.permitAll();
		assertThat(authorizationManager).isInstanceOf(SingleResultAuthorizationManager.class);
	}

	@Test
	public void denyAllReturnsSingleResultAuthorizationManagerByDefault() {
		AuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		AuthorizationManager<String> authorizationManager = factory.denyAll();
		assertThat(authorizationManager).isInstanceOf(SingleResultAuthorizationManager.class);
	}

	@Test
	public void hasRoleReturnsAuthorityAuthorizationManagerByDefault() {
		AuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		AuthorizationManager<String> authorizationManager = factory.hasRole("USER");
		assertThat(authorizationManager).isInstanceOf(AuthorityAuthorizationManager.class);
	}

	@Test
	public void hasAnyRoleReturnsAuthorityAuthorizationManagerByDefault() {
		AuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		AuthorizationManager<String> authorizationManager = factory.hasAnyRole("USER", "ADMIN");
		assertThat(authorizationManager).isInstanceOf(AuthorityAuthorizationManager.class);
	}

	@Test
	public void hasAllRolesReturnsAllAuthoritiesAuthorizationManagerByDefault() {
		AuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		AuthorizationManager<String> authorizationManager = factory.hasAllRoles("authority1", "authority2");
		assertThat(authorizationManager).isInstanceOf(AllAuthoritiesAuthorizationManager.class);
	}

	@Test
	public void hasAuthorityReturnsAuthorityAuthorizationManagerByDefault() {
		AuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		AuthorizationManager<String> authorizationManager = factory.hasAuthority("authority1");
		assertThat(authorizationManager).isInstanceOf(AuthorityAuthorizationManager.class);
	}

	@Test
	public void hasAnyAuthorityReturnsAuthorityAuthorizationManagerByDefault() {
		AuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		AuthorizationManager<String> authorizationManager = factory.hasAnyAuthority("authority1", "authority2");
		assertThat(authorizationManager).isInstanceOf(AuthorityAuthorizationManager.class);
	}

	@Test
	public void hasAllAuthoritiesReturnsAllAuthoritiesAuthorizationManagerByDefault() {
		AuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		AuthorizationManager<String> authorizationManager = factory.hasAllAuthorities("authority1", "authority2");
		assertThat(authorizationManager).isInstanceOf(AllAuthoritiesAuthorizationManager.class);
	}

	@Test
	public void authenticatedReturnsAuthenticatedAuthorizationManagerByDefault() {
		AuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		AuthorizationManager<String> authorizationManager = factory.authenticated();
		assertThat(authorizationManager).isInstanceOf(AuthenticatedAuthorizationManager.class);
	}

	@Test
	public void fullyAuthenticatedReturnsAuthenticatedAuthorizationManagerByDefault() {
		AuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		AuthorizationManager<String> authorizationManager = factory.fullyAuthenticated();
		assertThat(authorizationManager).isInstanceOf(AuthenticatedAuthorizationManager.class);
	}

	@Test
	public void rememberMeReturnsAuthenticatedAuthorizationManagerByDefault() {
		AuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		AuthorizationManager<String> authorizationManager = factory.rememberMe();
		assertThat(authorizationManager).isInstanceOf(AuthenticatedAuthorizationManager.class);
	}

	@Test
	public void anonymousReturnsAuthenticatedAuthorizationManagerByDefault() {
		AuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		AuthorizationManager<String> authorizationManager = factory.anonymous();
		assertThat(authorizationManager).isInstanceOf(AuthenticatedAuthorizationManager.class);
	}

}
