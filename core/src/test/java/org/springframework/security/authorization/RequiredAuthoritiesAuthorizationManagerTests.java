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

import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * Tests for {@link RequiredAuthoritiesAuthorizationManager}.
 *
 * @author Rob Winch
 * @since 7.0
 */
@ExtendWith(MockitoExtension.class)
class RequiredAuthoritiesAuthorizationManagerTests {

	@Mock
	private RequiredAuthoritiesRepository repository;

	private static final Object DOES_NOT_MATTER = "";

	private RequiredAuthoritiesAuthorizationManager<Object> manager;

	private Supplier<Authentication> authentication = () -> new TestingAuthenticationToken("user", "password",
			"ROLE_USER", "ROLE_ADMIN");

	@BeforeEach
	void setup() {
		this.manager = new RequiredAuthoritiesAuthorizationManager<>(this.repository);
	}

	@Test
	void constructorWhenNullRepositoryThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new RequiredAuthoritiesAuthorizationManager(null));
	}

	@Test
	void authorizeWhenNoResults() {
		returnAuthorities(Collections.emptyList());
		assertGranted();
	}

	@Test
	void authorizeWhenAdditionalAuthoriteisAndGranted() {
		returnAuthorities(
				this.authentication.get().getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
		assertGranted();
	}

	@Test
	void authorizeWhenAdditionalAuthoriteisAndDenied() {
		returnAuthorities(List.of("NOT_FOUND"));
		assertDenied();
	}

	@Test
	void authorizeWhenOneFoundAndDenied() {
		returnAuthorities(List.of("ROLE_USER", "NOT_FOUND"));
		assertDenied();
	}

	private void returnAuthorities(List<String> authorities) {
		given(this.repository.findRequiredAuthorities(any())).willReturn(authorities);
	}

	private void assertGranted() {
		AuthorizationResult authz = this.manager.authorize(this.authentication, DOES_NOT_MATTER);
		assertThat(authz.isGranted()).isTrue();
	}

	private void assertDenied() {
		AuthorizationResult authz = this.manager.authorize(this.authentication, DOES_NOT_MATTER);
		assertThat(authz.isGranted()).isFalse();
	}

}
