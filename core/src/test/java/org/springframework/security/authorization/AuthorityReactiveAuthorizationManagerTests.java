/*
 * Copyright 2002-2017 the original author or authors.
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

import java.util.Collections;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;

/**
 * @author Rob Winch
 * @since 5.0
 */
@ExtendWith(MockitoExtension.class)
public class AuthorityReactiveAuthorizationManagerTests {

	@Mock
	Authentication authentication;

	AuthorityReactiveAuthorizationManager<Object> manager = AuthorityReactiveAuthorizationManager.hasAuthority("ADMIN");

	@Test
	public void checkWhenHasAuthorityAndNotAuthenticatedThenReturnFalse() {
		boolean granted = this.manager.check(Mono.just(this.authentication), null).block().isGranted();
		assertThat(granted).isFalse();
	}

	@Test
	public void checkWhenHasAuthorityAndEmptyThenReturnFalse() {
		boolean granted = this.manager.check(Mono.empty(), null).block().isGranted();
		assertThat(granted).isFalse();
	}

	@Test
	public void checkWhenHasAuthorityAndErrorThenError() {
		Mono<AuthorizationDecision> result = this.manager.check(Mono.error(new RuntimeException("ooops")), null);
		// @formatter:off
		StepVerifier.create(result)
				.expectError()
				.verify();
		// @formatter:on
	}

	@Test
	public void checkWhenHasAuthorityAndAuthenticatedAndNoAuthoritiesThenReturnFalse() {
		given(this.authentication.isAuthenticated()).willReturn(true);
		given(this.authentication.getAuthorities()).willReturn(Collections.emptyList());
		boolean granted = this.manager.check(Mono.just(this.authentication), null).block().isGranted();
		assertThat(granted).isFalse();
	}

	@Test
	public void checkWhenHasAuthorityAndAuthenticatedAndWrongAuthoritiesThenReturnFalse() {
		this.authentication = new TestingAuthenticationToken("rob", "secret", "ROLE_ADMIN");
		boolean granted = this.manager.check(Mono.just(this.authentication), null).block().isGranted();
		assertThat(granted).isFalse();
	}

	@Test
	public void checkWhenHasAuthorityAndAuthorizedThenReturnTrue() {
		this.authentication = new TestingAuthenticationToken("rob", "secret", "ADMIN");
		boolean granted = this.manager.check(Mono.just(this.authentication), null).block().isGranted();
		assertThat(granted).isTrue();
	}

	@Test
	public void checkWhenHasCustomAuthorityAndAuthorizedThenReturnTrue() {
		GrantedAuthority customGrantedAuthority = () -> "ADMIN";
		this.authentication = new TestingAuthenticationToken("rob", "secret",
				Collections.singletonList(customGrantedAuthority));
		boolean granted = this.manager.check(Mono.just(this.authentication), null).block().isGranted();
		assertThat(granted).isTrue();
	}

	@Test
	public void checkWhenHasCustomAuthorityAndAuthenticatedAndWrongAuthoritiesThenReturnFalse() {
		GrantedAuthority customGrantedAuthority = () -> "USER";
		this.authentication = new TestingAuthenticationToken("rob", "secret",
				Collections.singletonList(customGrantedAuthority));
		boolean granted = this.manager.check(Mono.just(this.authentication), null).block().isGranted();
		assertThat(granted).isFalse();
	}

	@Test
	public void checkWhenHasRoleAndAuthorizedThenReturnTrue() {
		this.manager = AuthorityReactiveAuthorizationManager.hasRole("ADMIN");
		this.authentication = new TestingAuthenticationToken("rob", "secret", "ROLE_ADMIN");
		boolean granted = this.manager.check(Mono.just(this.authentication), null).block().isGranted();
		assertThat(granted).isTrue();
	}

	@Test
	public void checkWhenHasRoleAndNotAuthorizedThenReturnFalse() {
		this.manager = AuthorityReactiveAuthorizationManager.hasRole("ADMIN");
		this.authentication = new TestingAuthenticationToken("rob", "secret", "ADMIN");
		boolean granted = this.manager.check(Mono.just(this.authentication), null).block().isGranted();
		assertThat(granted).isFalse();
	}

	@Test
	public void checkWhenHasAnyRoleAndAuthorizedThenReturnTrue() {
		this.manager = AuthorityReactiveAuthorizationManager.hasAnyRole("GENERAL", "USER", "TEST");
		this.authentication = new TestingAuthenticationToken("rob", "secret", "ROLE_USER", "ROLE_AUDITING",
				"ROLE_ADMIN");
		boolean granted = this.manager.check(Mono.just(this.authentication), null).block().isGranted();
		assertThat(granted).isTrue();
	}

	@Test
	public void checkWhenHasAnyRoleAndNotAuthorizedThenReturnFalse() {
		this.manager = AuthorityReactiveAuthorizationManager.hasAnyRole("GENERAL", "USER", "TEST");
		this.authentication = new TestingAuthenticationToken("rob", "secret", "USER", "AUDITING", "ADMIN");
		boolean granted = this.manager.check(Mono.just(this.authentication), null).block().isGranted();
		assertThat(granted).isFalse();
	}

	@Test
	public void hasRoleWhenNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> AuthorityReactiveAuthorizationManager.hasRole((String) null));
	}

	@Test
	public void hasAuthorityWhenNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> AuthorityReactiveAuthorizationManager.hasAuthority((String) null));
	}

	@Test
	public void hasAnyRoleWhenNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> AuthorityReactiveAuthorizationManager.hasAnyRole((String) null));
	}

	@Test
	public void hasAnyAuthorityWhenNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> AuthorityReactiveAuthorizationManager.hasAnyAuthority((String) null));
	}

	@Test
	public void hasAnyRoleWhenOneIsNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> AuthorityReactiveAuthorizationManager.hasAnyRole("ROLE_ADMIN", (String) null));
	}

	@Test
	public void hasAnyAuthorityWhenOneIsNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> AuthorityReactiveAuthorizationManager.hasAnyAuthority("ADMIN", (String) null));
	}

}
