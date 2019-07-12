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

package org.springframework.security.webauthn.userdetails;


import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;
import org.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorImpl;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnAndPasswordUserTest {

	@Test
	public void getter_setter_test() {
		GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_ADMIN");
		WebAuthnAuthenticator authenticator = new WebAuthnAuthenticatorImpl(new byte[0], "dummy", new byte[0], 0, null, null);
		WebAuthnAndPasswordUser userDetails = new WebAuthnAndPasswordUser(
				new byte[32],
				"dummy",
				"dummy",
				Collections.singletonList(authenticator),
				Collections.singletonList(grantedAuthority));

		userDetails.setSingleFactorAuthenticationAllowed(true);
		assertThat(userDetails.getUserHandle()).isEqualTo(new byte[32]);
		assertThat(userDetails.isSingleFactorAuthenticationAllowed()).isTrue();
		assertThat(userDetails.getAuthenticators()).isEqualTo(Collections.singletonList(authenticator));
	}

}
