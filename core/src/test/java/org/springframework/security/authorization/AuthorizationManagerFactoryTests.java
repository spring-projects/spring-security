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

import org.springframework.security.authentication.TestAuthentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

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

	@Test
	public void anonymousWhenAdditionalAuthorizationThenNotInvoked() {
		AuthorizationManager<String> additional = mock(AuthorizationManager.class);
		DefaultAuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		factory.setAdditionalAuthorization(additional);

		factory.anonymous();

		verifyNoInteractions(additional);
	}

	@Test
	public void permitAllWhenAdditionalAuthorizationThenNotInvoked() {
		AuthorizationManager<String> additional = mock(AuthorizationManager.class);
		DefaultAuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		factory.setAdditionalAuthorization(additional);

		factory.permitAll();

		verifyNoInteractions(additional);
	}

	@Test
	public void denyAllAllWhenAdditionalAuthorizationThenNotInvoked() {
		AuthorizationManager<String> additional = mock(AuthorizationManager.class);
		DefaultAuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		factory.setAdditionalAuthorization(additional);

		factory.permitAll();

		verifyNoInteractions(additional);
	}

	@Test
	public void hasRoleWhenAdditionalAuthorizationThenInvoked() {
		AuthorizationManager<String> additional = mock(AuthorizationManager.class);
		given(additional.authorize(any(), any())).willReturn(new AuthorizationDecision(true),
				new AuthorizationDecision(false));
		DefaultAuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		factory.setAdditionalAuthorization(additional);

		assertUserGranted(factory.hasRole("USER"));
		assertUserDenied(factory.hasRole("USER"));

		verify(additional, times(2)).authorize(any(), any());

	}

	@Test
	public void hasAnyRoleWhenAdditionalAuthorizationThenInvoked() {
		AuthorizationManager<String> additional = mock(AuthorizationManager.class);
		given(additional.authorize(any(), any())).willReturn(new AuthorizationDecision(true),
				new AuthorizationDecision(false));
		DefaultAuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		factory.setAdditionalAuthorization(additional);

		assertUserGranted(factory.hasAnyRole("USER"));
		assertUserDenied(factory.hasAnyRole("USER"));

		verify(additional, times(2)).authorize(any(), any());

	}

	@Test
	public void hasAllRolesWhenAdditionalAuthorizationThenInvoked() {
		AuthorizationManager<String> additional = mock(AuthorizationManager.class);
		given(additional.authorize(any(), any())).willReturn(new AuthorizationDecision(true),
				new AuthorizationDecision(false));
		DefaultAuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		factory.setAdditionalAuthorization(additional);

		assertUserGranted(factory.hasAllRoles("USER"));
		assertUserDenied(factory.hasAllRoles("USER"));

		verify(additional, times(2)).authorize(any(), any());

	}

	@Test
	public void hasAuthorityWhenAdditionalAuthorizationThenInvoked() {
		AuthorizationManager<String> additional = mock(AuthorizationManager.class);
		given(additional.authorize(any(), any())).willReturn(new AuthorizationDecision(true),
				new AuthorizationDecision(false));
		DefaultAuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		factory.setAdditionalAuthorization(additional);

		assertUserGranted(factory.hasAuthority("ROLE_USER"));
		assertUserDenied(factory.hasAuthority("ROLE_USER"));

		verify(additional, times(2)).authorize(any(), any());

	}

	@Test
	public void hasAnyAuthorityWhenAdditionalAuthorizationThenInvoked() {
		AuthorizationManager<String> additional = mock(AuthorizationManager.class);
		given(additional.authorize(any(), any())).willReturn(new AuthorizationDecision(true),
				new AuthorizationDecision(false));
		DefaultAuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		factory.setAdditionalAuthorization(additional);

		assertUserGranted(factory.hasAnyAuthority("ROLE_USER"));
		assertUserDenied(factory.hasAnyAuthority("ROLE_USER"));

		verify(additional, times(2)).authorize(any(), any());

	}

	@Test
	public void hasAllAuthoritiesWhenAdditionalAuthorizationThenInvoked() {
		AuthorizationManager<String> additional = mock(AuthorizationManager.class);
		given(additional.authorize(any(), any())).willReturn(new AuthorizationDecision(true),
				new AuthorizationDecision(false));
		DefaultAuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		factory.setAdditionalAuthorization(additional);

		assertUserGranted(factory.hasAllAuthorities("ROLE_USER"));
		assertUserDenied(factory.hasAllAuthorities("ROLE_USER"));

		verify(additional, times(2)).authorize(any(), any());
	}

	@Test
	public void authenticatedWhenAdditionalAuthorizationThenInvoked() {
		AuthorizationManager<String> additional = mock(AuthorizationManager.class);
		given(additional.authorize(any(), any())).willReturn(new AuthorizationDecision(true),
				new AuthorizationDecision(false));
		DefaultAuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		factory.setAdditionalAuthorization(additional);

		assertUserGranted(factory.authenticated());
		assertUserDenied(factory.authenticated());

		verify(additional, times(2)).authorize(any(), any());
	}

	@Test
	public void fullyAuthenticatedWhenAdditionalAuthorizationThenInvoked() {
		AuthorizationManager<String> additional = mock(AuthorizationManager.class);
		given(additional.authorize(any(), any())).willReturn(new AuthorizationDecision(true),
				new AuthorizationDecision(false));
		DefaultAuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		factory.setAdditionalAuthorization(additional);

		assertUserGranted(factory.fullyAuthenticated());
		assertUserDenied(factory.fullyAuthenticated());

		verify(additional, times(2)).authorize(any(), any());
	}

	@Test
	public void rememberMeWhenAdditionalAuthorizationThenInvoked() {
		AuthorizationManager<String> additional = mock(AuthorizationManager.class);
		given(additional.authorize(any(), any())).willReturn(new AuthorizationDecision(true),
				new AuthorizationDecision(false));
		DefaultAuthorizationManagerFactory<String> factory = new DefaultAuthorizationManagerFactory<>();
		factory.setAdditionalAuthorization(additional);

		assertThat(factory.rememberMe().authorize(() -> TestAuthentication.rememberMeUser(), "").isGranted()).isTrue();
		assertThat(factory.rememberMe().authorize(() -> TestAuthentication.rememberMeUser(), "").isGranted()).isFalse();

		verify(additional, times(2)).authorize(any(), any());
	}

	@Test
	public void builderWhenEmptyAdditionalAuthoritiesThenIllegalStateException() {
		AuthorizationManagerFactories.AdditionalRequiredFactorsBuilder<Object> builder = AuthorizationManagerFactories
			.multiFactor();
		assertThatIllegalStateException().isThrownBy(() -> builder.build());
	}

	@Test
	public void builderWhenAdditionalAuthorityThenRequired() {
		AuthorizationManagerFactory<String> factory = AuthorizationManagerFactories.<String>multiFactor()
			.requireFactors("ROLE_ADMIN")
			.build();
		assertUserDenied(factory.hasRole("USER"));
		assertThat(factory.hasRole("USER").authorize(() -> TestAuthentication.authenticatedAdmin(), "").isGranted())
			.isTrue();
	}

	@Test
	public void builderWhenAdditionalAuthoritiesThenRequired() {
		AuthorizationManagerFactory<String> factory = AuthorizationManagerFactories.<String>multiFactor()
			.requireFactors("ROLE_ADMIN", "ROLE_USER")
			.build();
		assertUserDenied(factory.hasRole("USER"));
		assertThat(factory.hasRole("USER").authorize(() -> TestAuthentication.authenticatedAdmin(), "").isGranted())
			.isTrue();
	}

	private void assertUserGranted(AuthorizationManager<String> manager) {
		assertThat(manager.authorize(() -> TestAuthentication.authenticatedUser(), "").isGranted()).isTrue();
	}

	private void assertUserDenied(AuthorizationManager<String> manager) {
		assertThat(manager.authorize(() -> TestAuthentication.authenticatedUser(), "").isGranted()).isFalse();
	}

}
