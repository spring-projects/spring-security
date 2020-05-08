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

	@Mock
	private WithMockOidcUser withUser;

	private WithMockOidcUserSecurityContextFactory factory;

	@Before
	public void setup() {
		factory = new WithMockOidcUserSecurityContextFactory();
		when(withUser.value()).thenReturn("valueUser");
		when(withUser.clientId()).thenReturn("clientId");
		when(withUser.authorities()).thenReturn(new String[] { WithMockOidcUser.DEFAULT_SCOPE });
		when(withUser.nameTokenClaim()).thenReturn("sub");
		when(withUser.name()).thenReturn("");
	}

	@Test(expected = IllegalArgumentException.class)
	public void userNameValueNullRaiseException() {
		when(withUser.value()).thenReturn(null);
		factory.createSecurityContext(withUser);
	}

	public void valueDefaultsUserIdWhenUserNameIsNull() {
		when(withUser.name()).thenReturn(null);
		assertThat(factory.createSecurityContext(withUser).getAuthentication().getName())
				.isEqualTo("valueUser");
	}

	@Test
	public void valueDefaultsUserIdWhenUserNameIsNotSet() {
		assertThat(factory.createSecurityContext(withUser).getAuthentication().getName())
				.isEqualTo("valueUser");
	}

	@Test
	public void userNamePrioritizedOverValue() {
		when(withUser.name()).thenReturn("customUser");

		assertThat(factory.createSecurityContext(withUser).getAuthentication().getName())
				.isEqualTo("customUser");
	}

	@Test
	public void overwriteAuthorities() {
		when(withUser.authorities()).thenReturn(new String[] { "USER", "CUSTOM" });

		assertThat(
				factory.createSecurityContext(withUser).getAuthentication()
						.getAuthorities()).extracting("authority").containsOnly(
				"USER", "CUSTOM");
	}

	@SuppressWarnings("checkstyle:WhitespaceAfter")
	@Test
	public void overwriteNameTokenClaim() {
		when(withUser.nameTokenClaim()).thenReturn("userNameClaim");

		Object authn = factory.createSecurityContext(withUser).getAuthentication().getPrincipal();
		assertThat(authn).isInstanceOf(OidcUser.class);
		assertThat(((OidcUser) authn).getClaims()).containsKey("userNameClaim");
		assertThat(((OidcUser) authn).getClaims()).doesNotContainKey("sub");
		assertThat(((OidcUser) authn).getName()).isEqualTo("valueUser");
	}

	@Test
	public void claimNotExpired() {
		when(withUser.nameTokenClaim()).thenReturn("userNameClaim");

		OidcUser oidcUser = (OidcUser) factory.createSecurityContext(withUser).getAuthentication().getPrincipal();
		assertThat(oidcUser.getIssuedAt().compareTo(Instant.now())).isNegative();
		assertThat(oidcUser.getExpiresAt().compareTo(Instant.now())).isPositive();
	}

}
