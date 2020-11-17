/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.core;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link ClientAuthenticationMethod}.
 *
 * @author Joe Grandja
 */
public class ClientAuthenticationMethodTests {

	@Test
	public void constructorWhenValueIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new ClientAuthenticationMethod(null));
	}

	@Test
	public void getValueWhenAuthenticationMethodBasicThenReturnBasic() {
		assertThat(ClientAuthenticationMethod.BASIC.getValue()).isEqualTo("basic");
	}

	@Test
	public void getValueWhenAuthenticationMethodClientSecretBasicThenReturnClientSecretBasic() {
		assertThat(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue()).isEqualTo("client_secret_basic");
	}

	@Test
	public void getValueWhenAuthenticationMethodPostThenReturnPost() {
		assertThat(ClientAuthenticationMethod.POST.getValue()).isEqualTo("post");
	}

	@Test
	public void getValueWhenAuthenticationMethodClientSecretPostThenReturnClientSecretPost() {
		assertThat(ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue()).isEqualTo("client_secret_post");
	}

	@Test
	public void getValueWhenAuthenticationMethodClientSecretJwtThenReturnClientSecretJwt() {
		assertThat(ClientAuthenticationMethod.CLIENT_SECRET_JWT.getValue()).isEqualTo("client_secret_jwt");
	}

	@Test
	public void getValueWhenAuthenticationMethodPrivateKeyJwtThenReturnPrivateKeyJwt() {
		assertThat(ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue()).isEqualTo("private_key_jwt");
	}

	@Test
	public void getValueWhenAuthenticationMethodNoneThenReturnNone() {
		assertThat(ClientAuthenticationMethod.NONE.getValue()).isEqualTo("none");
	}

}
