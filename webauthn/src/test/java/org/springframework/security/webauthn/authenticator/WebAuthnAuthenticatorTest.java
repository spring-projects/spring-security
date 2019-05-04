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

package org.springframework.security.webauthn.authenticator;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class WebAuthnAuthenticatorTest {

	@Test
	public void equals_hashCode_test() {
		WebAuthnAuthenticator instanceA = new WebAuthnAuthenticator("authenticator", null, null, 0);
		WebAuthnAuthenticator instanceB = new WebAuthnAuthenticator("authenticator", null, null, 0);
		assertThat(instanceA).isEqualTo(instanceB);
		assertThat(instanceA).hasSameHashCodeAs(instanceB);
	}

	@Test
	public void get_set_name_test() {
		WebAuthnAuthenticator instance = new WebAuthnAuthenticator("authenticator", null, null, 0);
		assertThat(instance.getName()).isEqualTo("authenticator");
		instance.setName("newName");
		assertThat(instance.getName()).isEqualTo("newName");
	}
}
