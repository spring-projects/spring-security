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

package org.springframework.security.authentication.rememberme;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.RememberMeAuthenticationProvider;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests {@link RememberMeAuthenticationProvider}.
 *
 * @author Ben Alex
 */
public class RememberMeAuthenticationProviderTests {

	@Test
	public void testDetectsAnInvalidKey() {
		RememberMeAuthenticationProvider aap = new RememberMeAuthenticationProvider("qwerty");
		RememberMeAuthenticationToken token = new RememberMeAuthenticationToken("WRONG_KEY", "Test",
				AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));
		assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> aap.authenticate(token));
	}

	@Test
	public void testDetectsMissingKey() {
		assertThatIllegalArgumentException().isThrownBy(() -> new RememberMeAuthenticationProvider(null));
	}

	@Test
	public void testGettersSetters() throws Exception {
		RememberMeAuthenticationProvider aap = new RememberMeAuthenticationProvider("qwerty");
		aap.afterPropertiesSet();
		assertThat(aap.getKey()).isEqualTo("qwerty");
	}

	@Test
	public void testIgnoresClassesItDoesNotSupport() {
		RememberMeAuthenticationProvider aap = new RememberMeAuthenticationProvider("qwerty");
		TestingAuthenticationToken token = new TestingAuthenticationToken("user", "password", "ROLE_A");
		assertThat(aap.supports(TestingAuthenticationToken.class)).isFalse();
		// Try it anyway
		assertThat(aap.authenticate(token)).isNull();
	}

	@Test
	public void testNormalOperation() {
		RememberMeAuthenticationProvider aap = new RememberMeAuthenticationProvider("qwerty");
		RememberMeAuthenticationToken token = new RememberMeAuthenticationToken("qwerty", "Test",
				AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));
		Authentication result = aap.authenticate(token);
		assertThat(token).isEqualTo(result);
	}

	@Test
	public void testSupports() {
		RememberMeAuthenticationProvider aap = new RememberMeAuthenticationProvider("qwerty");
		assertThat(aap.supports(RememberMeAuthenticationToken.class)).isTrue();
		assertThat(aap.supports(TestingAuthenticationToken.class)).isFalse();
	}

}
