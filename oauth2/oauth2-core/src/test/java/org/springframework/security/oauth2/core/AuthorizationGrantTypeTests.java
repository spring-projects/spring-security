/*
 * Copyright 2002-2025 the original author or authors.
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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link AuthorizationGrantType}.
 *
 * @author Joe Grandja
 */
public class AuthorizationGrantTypeTests {

	@Test
	public void constructorWhenValueIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new AuthorizationGrantType(null));
	}

	@Test
	public void getValueWhenAuthorizationCodeGrantTypeThenReturnAuthorizationCode() {
		assertThat(AuthorizationGrantType.AUTHORIZATION_CODE.getValue()).isEqualTo("authorization_code");
	}

	@Test
	public void getValueWhenRefreshTokenGrantTypeThenReturnRefreshToken() {
		assertThat(AuthorizationGrantType.REFRESH_TOKEN.getValue()).isEqualTo("refresh_token");
	}

	@Test
	public void getValueWhenJwtBearerGrantTypeThenReturnJwtBearer() {
		assertThat(AuthorizationGrantType.JWT_BEARER.getValue())
			.isEqualTo("urn:ietf:params:oauth:grant-type:jwt-bearer");
	}

}
