/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.authentication;

import org.junit.Test;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests {@link TestingAuthenticationProvider}.
 *
 * @author Ben Alex
 */
public class TestingAuthenticationProviderTests {

	@Test
	public void testAuthenticates() {
		TestingAuthenticationProvider provider = new TestingAuthenticationProvider();
		TestingAuthenticationToken token = new TestingAuthenticationToken("Test", "Password", "ROLE_ONE", "ROLE_TWO");
		Authentication result = provider.authenticate(token);
		assertThat(result instanceof TestingAuthenticationToken).isTrue();
		TestingAuthenticationToken castResult = (TestingAuthenticationToken) result;
		assertThat(castResult.getPrincipal()).isEqualTo("Test");
		assertThat(castResult.getCredentials()).isEqualTo("Password");
		assertThat(AuthorityUtils.authorityListToSet(castResult.getAuthorities())).contains("ROLE_ONE", "ROLE_TWO");
	}

	@Test
	public void testSupports() {
		TestingAuthenticationProvider provider = new TestingAuthenticationProvider();
		assertThat(provider.supports(TestingAuthenticationToken.class)).isTrue();
		assertThat(!provider.supports(String.class)).isTrue();
	}

}
