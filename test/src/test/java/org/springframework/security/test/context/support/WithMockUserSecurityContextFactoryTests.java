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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class WithMockUserSecurityContextFactoryTests {

	@Mock
	private WithMockUser withUser;

	private WithMockUserSecurityContextFactory factory;

	@Before
	public void setup() {
		this.factory = new WithMockUserSecurityContextFactory();
	}

	@Test(expected = IllegalArgumentException.class)
	public void usernameNull() {
		this.factory.createSecurityContext(this.withUser);
	}

	@Test
	public void valueDefaultsUsername() {
		when(this.withUser.value()).thenReturn("valueUser");
		when(this.withUser.password()).thenReturn("password");
		when(this.withUser.roles()).thenReturn(new String[] { "USER" });
		when(this.withUser.authorities()).thenReturn(new String[] {});

		assertThat(this.factory.createSecurityContext(this.withUser).getAuthentication().getName())
				.isEqualTo(this.withUser.value());
	}

	@Test
	public void usernamePrioritizedOverValue() {
		when(this.withUser.username()).thenReturn("customUser");
		when(this.withUser.password()).thenReturn("password");
		when(this.withUser.roles()).thenReturn(new String[] { "USER" });
		when(this.withUser.authorities()).thenReturn(new String[] {});

		assertThat(this.factory.createSecurityContext(this.withUser).getAuthentication().getName())
				.isEqualTo(this.withUser.username());
	}

	@Test
	public void rolesWorks() {
		when(this.withUser.value()).thenReturn("valueUser");
		when(this.withUser.password()).thenReturn("password");
		when(this.withUser.roles()).thenReturn(new String[] { "USER", "CUSTOM" });
		when(this.withUser.authorities()).thenReturn(new String[] {});

		assertThat(this.factory.createSecurityContext(this.withUser).getAuthentication().getAuthorities())
				.extracting("authority").containsOnly("ROLE_USER", "ROLE_CUSTOM");
	}

	@Test
	public void authoritiesWorks() {
		when(this.withUser.value()).thenReturn("valueUser");
		when(this.withUser.password()).thenReturn("password");
		when(this.withUser.roles()).thenReturn(new String[] { "USER" });
		when(this.withUser.authorities()).thenReturn(new String[] { "USER", "CUSTOM" });

		assertThat(this.factory.createSecurityContext(this.withUser).getAuthentication().getAuthorities())
				.extracting("authority").containsOnly("USER", "CUSTOM");
	}

	@Test(expected = IllegalStateException.class)
	public void authoritiesAndRolesInvalid() {
		when(this.withUser.value()).thenReturn("valueUser");
		when(this.withUser.roles()).thenReturn(new String[] { "CUSTOM" });
		when(this.withUser.authorities()).thenReturn(new String[] { "USER", "CUSTOM" });

		this.factory.createSecurityContext(this.withUser);
	}

	@Test(expected = IllegalArgumentException.class)
	public void rolesWithRolePrefixFails() {
		when(this.withUser.value()).thenReturn("valueUser");
		when(this.withUser.roles()).thenReturn(new String[] { "ROLE_FAIL" });
		when(this.withUser.authorities()).thenReturn(new String[] {});

		this.factory.createSecurityContext(this.withUser);
	}

}
