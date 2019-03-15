/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.jwt;

import com.nimbusds.jose.jwk.JWK;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * @author Rob Winch
 * @since 5.1
 */
public class JWKContextTests {

	@Test
	public void constructorWhenNullThenIllegalArgumentException() {
		List<JWK> jwkList = null;
		assertThatCode(() -> new JWKContext(jwkList))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void getJwkListWhenEmpty() {
		JWKContext jwkContext = new JWKContext(Collections.emptyList());
		assertThat(jwkContext.getJwkList()).isEmpty();
	}

	@Test
	public void getJwkListWhenNotEmpty() {
		JWK key = mock(JWK.class);
		JWKContext jwkContext = new JWKContext(Arrays.asList(key));
		assertThat(jwkContext.getJwkList()).containsOnly(key);
	}
}
