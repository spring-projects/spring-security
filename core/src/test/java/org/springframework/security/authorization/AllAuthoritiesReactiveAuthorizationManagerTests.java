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

import java.util.ArrayList;
import java.util.Collection;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class AllAuthoritiesReactiveAuthorizationManagerTests {

	public static final String ROLE_USER = "ROLE_USER";

	public static final String ROLE_ADMIN = "ROLE_ADMIN";

	@Mock
	private RoleHierarchy roleHierarchy;

	@Captor
	private ArgumentCaptor<Collection<? extends GrantedAuthority>> authoritiesCaptor;

	@Test
	void hasAllAuthoritiesWhenNullAuthoritiesThenIllegalArgumentException() {
		String[] requiredAuthorities = null;
		assertThatIllegalArgumentException()
			.isThrownBy(() -> AllAuthoritiesReactiveAuthorizationManager.hasAllAuthorities(requiredAuthorities));
	}

	@Test
	void hasAllAuthortiesWhenEmptyAuthoritiesThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> AllAuthoritiesReactiveAuthorizationManager.hasAllAuthorities((new String[0])));
	}

	@Test
	void authorizeWhenGranted() {
		Authentication authentication = new TestingAuthenticationToken("user", "password", ROLE_USER);
		AllAuthoritiesReactiveAuthorizationManager<Object> manager = AllAuthoritiesReactiveAuthorizationManager
			.hasAllAuthorities(ROLE_USER);
		assertThat(manager.authorize(Mono.just(authentication), "").block().isGranted()).isTrue();
	}

	@Test
	void authorizeWhenNotAuthenticated() {
		Authentication authentication = new TestingAuthenticationToken("user", "password", ROLE_USER);
		authentication.setAuthenticated(false);
		AllAuthoritiesReactiveAuthorizationManager<Object> manager = AllAuthoritiesReactiveAuthorizationManager
			.hasAllAuthorities(ROLE_USER);
		assertThat(manager.authorize(Mono.just(authentication), "").block().isGranted()).isFalse();
	}

	@Test
	void hasAllRolesAuthorizeWhenGranted() {
		Authentication authentication = new TestingAuthenticationToken("user", "password", ROLE_USER);
		AllAuthoritiesReactiveAuthorizationManager<Object> manager = AllAuthoritiesReactiveAuthorizationManager
			.hasAllRoles("USER");
		assertThat(manager.authorize(Mono.just(authentication), "").block().isGranted()).isTrue();
	}

	@Test
	void hasAllPrefixedAuthoritiesAuthorizeWhenGranted() {
		String prefix = "PREFIX_";
		String authority1 = "AUTHORITY1";
		String authority2 = "AUTHORITY2";
		Authentication authentication = new TestingAuthenticationToken("user", "password", prefix + authority1,
				prefix + authority2);
		AllAuthoritiesReactiveAuthorizationManager<Object> manager = AllAuthoritiesReactiveAuthorizationManager
			.hasAllPrefixedAuthorities(prefix, authority1, authority2);
		assertThat(manager.authorize(Mono.just(authentication), "").block().isGranted()).isTrue();
	}

	@Test
	void authorizeWhenSingleMissingThenDenied() {
		Authentication authentication = new TestingAuthenticationToken("user", "password", ROLE_USER);
		AllAuthoritiesReactiveAuthorizationManager<Object> manager = AllAuthoritiesReactiveAuthorizationManager
			.hasAllAuthorities(ROLE_ADMIN);
		assertThat(manager.authorize(Mono.just(authentication), "").block().isGranted()).isFalse();
	}

	@Test
	void authorizeWhenMultipleMissingOneThenDenied() {
		Authentication authentication = new TestingAuthenticationToken("user", "password", ROLE_USER);
		AllAuthoritiesReactiveAuthorizationManager<Object> manager = AllAuthoritiesReactiveAuthorizationManager
			.hasAllAuthorities(ROLE_ADMIN, ROLE_USER);
		AuthorityAuthorizationDecision result = manager.authorize(Mono.just(authentication), "")
			.cast(AuthorityAuthorizationDecision.class)
			.block();
		assertThat(result.isGranted()).isFalse();
		assertThat(result.getAuthorities()).hasSize(1);
		assertThat(new ArrayList<>(result.getAuthorities()).get(0).getAuthority()).isEqualTo(ROLE_ADMIN);
	}

	@Test
	void setRoleHierarchyWhenNullThenIllegalArgumentException() {
		AllAuthoritiesReactiveAuthorizationManager<?> manager = AllAuthoritiesReactiveAuthorizationManager
			.hasAllAuthorities(ROLE_USER);
		assertThatIllegalArgumentException().isThrownBy(() -> manager.setRoleHierarchy(null));
	}

	@Test
	void setRoleHierarchyThenUsesResult() {
		Collection result = AuthorityUtils.createAuthorityList(ROLE_USER, ROLE_ADMIN);
		given(this.roleHierarchy.getReachableGrantedAuthorities(any())).willReturn(result);
		AllAuthoritiesReactiveAuthorizationManager<Object> manager = AllAuthoritiesReactiveAuthorizationManager
			.hasAllAuthorities(ROLE_USER);
		manager.setRoleHierarchy(this.roleHierarchy);

		Authentication authentication = new TestingAuthenticationToken("user", "password", ROLE_USER);

		AuthorityAuthorizationDecision authz = manager.authorize(Mono.just(authentication), "")
			.cast(AuthorityAuthorizationDecision.class)
			.block();
		assertThat(authz.isGranted()).isTrue();
		verify(this.roleHierarchy).getReachableGrantedAuthorities(this.authoritiesCaptor.capture());
		assertThat(this.authoritiesCaptor.getValue()).map(GrantedAuthority::getAuthority).contains(ROLE_USER);
	}

}
