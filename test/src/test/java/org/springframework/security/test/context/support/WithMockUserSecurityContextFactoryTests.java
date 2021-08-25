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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
public class WithMockUserSecurityContextFactoryTests {

	@Mock
	private WithMockUser withUser;

	private WithMockUserSecurityContextFactory factory;

	@BeforeEach
	public void setup() {
		this.factory = new WithMockUserSecurityContextFactory();
	}

	@Test
	public void usernameNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.factory.createSecurityContext(this.withUser));
	}

	@Test
	public void valueDefaultsUsername() {
		given(this.withUser.value()).willReturn("valueUser");
		given(this.withUser.password()).willReturn("password");
		given(this.withUser.roles()).willReturn(new String[] { "USER" });
		given(this.withUser.authorities()).willReturn(new String[] {});
		assertThat(this.factory.createSecurityContext(this.withUser).getAuthentication().getName())
				.isEqualTo(this.withUser.value());
	}

	@Test
	public void usernamePrioritizedOverValue() {
		given(this.withUser.username()).willReturn("customUser");
		given(this.withUser.password()).willReturn("password");
		given(this.withUser.roles()).willReturn(new String[] { "USER" });
		given(this.withUser.authorities()).willReturn(new String[] {});
		assertThat(this.factory.createSecurityContext(this.withUser).getAuthentication().getName())
				.isEqualTo(this.withUser.username());
	}

	@Test
	public void rolesWorks() {
		given(this.withUser.value()).willReturn("valueUser");
		given(this.withUser.password()).willReturn("password");
		given(this.withUser.roles()).willReturn(new String[] { "USER", "CUSTOM" });
		given(this.withUser.authorities()).willReturn(new String[] {});
		assertThat(this.factory.createSecurityContext(this.withUser).getAuthentication().getAuthorities())
				.extracting("authority").containsOnly("ROLE_USER", "ROLE_CUSTOM");
	}

	@Test
	public void authoritiesWorks() {
		given(this.withUser.value()).willReturn("valueUser");
		given(this.withUser.password()).willReturn("password");
		given(this.withUser.roles()).willReturn(new String[] { "USER" });
		given(this.withUser.authorities()).willReturn(new String[] { "USER", "CUSTOM" });
		assertThat(this.factory.createSecurityContext(this.withUser).getAuthentication().getAuthorities())
				.extracting("authority").containsOnly("USER", "CUSTOM");
	}

	@Test
	public void authoritiesAndRolesInvalid() {
		given(this.withUser.value()).willReturn("valueUser");
		given(this.withUser.roles()).willReturn(new String[] { "CUSTOM" });
		given(this.withUser.authorities()).willReturn(new String[] { "USER", "CUSTOM" });
		assertThatIllegalStateException().isThrownBy(() -> this.factory.createSecurityContext(this.withUser));
	}

	@Test
	public void rolesWithRolePrefixFails() {
		given(this.withUser.value()).willReturn("valueUser");
		given(this.withUser.roles()).willReturn(new String[] { "ROLE_FAIL" });
		given(this.withUser.authorities()).willReturn(new String[] {});
		assertThatIllegalArgumentException().isThrownBy(() -> this.factory.createSecurityContext(this.withUser));
	}

}
