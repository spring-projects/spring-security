/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.test.context.support;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;

@RunWith(MockitoJUnitRunner.class)
public class WithMockOidcUserSecurityContextTests {
	private final static String USER_VALUE = "valueUser";

	@Mock
	private WithMockOidcUser withUser;

	private WithMockOidcUserSecurityContextFactory factory;

	@Before
	public void setup() {
		factory = new WithMockOidcUserSecurityContextFactory();
		when(withUser.value()).thenReturn(USER_VALUE);
		when(withUser.authorities()).thenReturn(new String[]{});
		when(withUser.scopes()).thenReturn(new String[]{"openid"});
		when(withUser.name()).thenReturn("");
	}

	@Test(expected = IllegalArgumentException.class)
	public void createSecurityContextWhenValueIsNullThenRaiseException() {
		when(withUser.value()).thenReturn(null);
		factory.createSecurityContext(withUser);
	}

	@Test
	public void createSecurityContextWhenUserNameIsNullThenUseDefaultValue() {
		when(withUser.name()).thenReturn(null);
		assertThat(factory.createSecurityContext(withUser).getAuthentication().getName())
				.isEqualTo(USER_VALUE);
	}

	@Test
	public void createSecurityContextWhenUserNameIsEmptyThenUseDefaultValue() {
		assertThat(factory.createSecurityContext(withUser).getAuthentication().getName())
				.isEqualTo(USER_VALUE);
	}

	@Test
	public void createSecurityContextWhenUserNameIsSetThenUseUserName() {
		when(withUser.name()).thenReturn(USER_VALUE);

		assertThat(factory.createSecurityContext(withUser).getAuthentication().getName())
				.isEqualTo(USER_VALUE);
	}

	@Test
	public void createSecurityContextWhenAuthoritiesSetThenUseAuthorities() {
		when(withUser.authorities()).thenReturn(new String[]{"USER", "CUSTOM", "ROLE_USER"});

		assertThat(
				factory.createSecurityContext(withUser).getAuthentication()
						.getAuthorities()).extracting("authority").containsExactlyInAnyOrder(
				"USER", "CUSTOM", "ROLE_USER");
	}

	@Test
	public void createSecurityContextWhenNoScopesAndAuthoritiesSetThenUseDefaultScope() {
		assertThat(
				factory.createSecurityContext(withUser).getAuthentication()
						.getAuthorities()).extracting("authority").containsExactlyInAnyOrder(
				"SCOPE_openid", "ROLE_USER");
	}

	@Test
	public void createSecurityContextWhenScopesSetThenUseScopes() {
		when(withUser.scopes()).thenReturn(new String[]{"DISPLAY", "ADMIN"});

		assertThat(
				factory.createSecurityContext(withUser).getAuthentication()
						.getAuthorities()).extracting("authority").containsExactlyInAnyOrder(
				"SCOPE_DISPLAY", "SCOPE_ADMIN", "ROLE_USER");
	}

	@Test
	public void createSecurityContextThenOidcNotYetExpired() {
		OidcUser oidcUser = (OidcUser) factory.createSecurityContext(withUser).getAuthentication().getPrincipal();
		assertThat(oidcUser.getIssuedAt().compareTo(Instant.now())).isNegative();
		assertThat(oidcUser.getExpiresAt().compareTo(Instant.now())).isPositive();
	}
}
