/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.webauthn;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Test for WebAuthnAuthenticationToken
 */
public class WebAuthnAuthenticationTokenTest {

	/**
	 * Verifies that constructor with 3 args yields authenticated authenticator.
	 */
	@Test
	public void webAuthnAuthenticationToken() {
		WebAuthnAuthenticationToken webAuthnAuthenticationToken = new WebAuthnAuthenticationToken(null, null, null);
		assertThat(webAuthnAuthenticationToken.isAuthenticated()).isTrue();
	}

	/**
	 * Verifies that getter returns constructor parameters
	 */
	@Test
	public void test_methods() {
		WebAuthnAuthenticationData credential = mock(WebAuthnAuthenticationData.class);
		WebAuthnAuthenticationToken webAuthnAuthenticationToken = new WebAuthnAuthenticationToken("username", credential, null);

		assertThat(webAuthnAuthenticationToken.getPrincipal()).isEqualTo("username");
		assertThat(webAuthnAuthenticationToken.getCredentials()).isEqualTo(credential);
	}

	@Test
	public void equals_hashCode_test() {
		WebAuthnAuthenticationData credential = mock(WebAuthnAuthenticationData.class);
		WebAuthnAuthenticationToken tokenA = new WebAuthnAuthenticationToken("username", credential, null);
		WebAuthnAuthenticationToken tokenB = new WebAuthnAuthenticationToken("username", credential, null);
		assertThat(tokenA).isEqualTo(tokenB);
		assertThat(tokenA).hasSameHashCodeAs(tokenB);
	}


}
