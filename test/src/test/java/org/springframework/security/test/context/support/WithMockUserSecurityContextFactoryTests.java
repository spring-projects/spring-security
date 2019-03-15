/*
 * Copyright 2002-2014 the original author or authors.
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

@RunWith(MockitoJUnitRunner.class)
public class WithMockUserSecurityContextFactoryTests {

	@Mock
	private WithMockUser withUser;

	private WithMockUserSecurityContextFactory factory;

	@Before
	public void setup() {
		factory = new WithMockUserSecurityContextFactory();
	}

	@Test(expected = IllegalArgumentException.class)
	public void usernameNull() {
		factory.createSecurityContext(withUser);
	}

	@Test
	public void valueDefaultsUsername() {
		when(withUser.value()).thenReturn("valueUser");
		when(withUser.password()).thenReturn("password");
		when(withUser.roles()).thenReturn(new String[] { "USER" });
		when(withUser.authorities()).thenReturn(new String[] {});

		assertThat(factory.createSecurityContext(withUser).getAuthentication().getName())
				.isEqualTo(withUser.value());
	}

	@Test
	public void usernamePrioritizedOverValue() {
		when(withUser.username()).thenReturn("customUser");
		when(withUser.password()).thenReturn("password");
		when(withUser.roles()).thenReturn(new String[] { "USER" });
		when(withUser.authorities()).thenReturn(new String[] {});

		assertThat(factory.createSecurityContext(withUser).getAuthentication().getName())
				.isEqualTo(withUser.username());
	}

	@Test
	public void rolesWorks() {
		when(withUser.value()).thenReturn("valueUser");
		when(withUser.password()).thenReturn("password");
		when(withUser.roles()).thenReturn(new String[] { "USER", "CUSTOM" });
		when(withUser.authorities()).thenReturn(new String[] {});

		assertThat(
				factory.createSecurityContext(withUser).getAuthentication()
						.getAuthorities()).extracting("authority").containsOnly(
				"ROLE_USER", "ROLE_CUSTOM");
	}

	@Test
	public void authoritiesWorks() {
		when(withUser.value()).thenReturn("valueUser");
		when(withUser.password()).thenReturn("password");
		when(withUser.roles()).thenReturn(new String[] { "USER" });
		when(withUser.authorities()).thenReturn(new String[] { "USER", "CUSTOM" });

		assertThat(
				factory.createSecurityContext(withUser).getAuthentication()
						.getAuthorities()).extracting("authority").containsOnly(
				"USER", "CUSTOM");
	}

	@Test(expected = IllegalStateException.class)
	public void authoritiesAndRolesInvalid() {
		when(withUser.value()).thenReturn("valueUser");
		when(withUser.roles()).thenReturn(new String[] { "CUSTOM" });
		when(withUser.authorities()).thenReturn(new String[] { "USER", "CUSTOM" });

		factory.createSecurityContext(withUser);
	}

	@Test(expected = IllegalArgumentException.class)
	public void rolesWithRolePrefixFails() {
		when(withUser.value()).thenReturn("valueUser");
		when(withUser.roles()).thenReturn(new String[] { "ROLE_FAIL" });
		when(withUser.authorities()).thenReturn(new String[] {});

		factory.createSecurityContext(withUser);
	}
}
