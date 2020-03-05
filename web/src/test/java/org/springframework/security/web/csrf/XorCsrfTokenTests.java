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
package org.springframework.security.web.csrf;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.Test;

/**
 * @author Ruby Hartono
 *
 */
public class XorCsrfTokenTests {
	private final String headerName = "headerName";
	private final String parameterName = "parameterName";
	private final String tokenValue = "tokenValue";

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullHeaderName() {
		new XorCsrfToken(null, parameterName, tokenValue);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEmptyHeaderName() {
		new XorCsrfToken("", parameterName, tokenValue);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullParameterName() {
		new XorCsrfToken(headerName, null, tokenValue);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEmptyParameterName() {
		new XorCsrfToken(headerName, "", tokenValue);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullTokenValue() {
		new XorCsrfToken(headerName, parameterName, null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEmptyTokenValue() {
		new XorCsrfToken(headerName, parameterName, "");
	}

	@Test
	public void matchesTokenValue() {
		String tokenStr = "123456";
		XorCsrfToken token = new XorCsrfToken(headerName, parameterName, tokenStr);
		String randomCsrfToken = token.getToken();
		String randomCsrfToken2 = token.getToken();

		assertThat(token.getToken()).isNotEqualTo(randomCsrfToken);
		assertThat(token.getToken()).isNotEqualTo(randomCsrfToken2);
		assertThat(randomCsrfToken).isNotEqualTo(randomCsrfToken2);
		assertThat(token.matches(randomCsrfToken)).isTrue();
		assertThat(token.matches(randomCsrfToken2)).isTrue();
	}

	@Test
	public void notMatchesTokenValue() {
		XorCsrfToken token1 = new XorCsrfToken(headerName, parameterName, "token1");
		XorCsrfToken token2 = new XorCsrfToken(headerName, parameterName, "token2");
		String randomCsrfToken1 = token1.getToken();
		String randomCsrfToken2 = token2.getToken();

		assertThat(randomCsrfToken1).isNotEqualTo(randomCsrfToken2);
		assertThat(token1.matches(randomCsrfToken2)).isFalse();
		assertThat(token2.matches(randomCsrfToken1)).isFalse();
	}

	@Test
	public void createGenerateTokenProviderShouldReturnInstanceWithSameBehaviorAsConstructorCreation() {
		XorCsrfToken token1 = new XorCsrfToken(headerName, parameterName, "token1");
		XorCsrfToken tokenFromProvider = XorCsrfToken.createGenerateTokenProvider().generateToken(headerName,
				parameterName, "token1");
		String randomCsrfToken1 = token1.getToken();
		String randomCsrfToken2 = tokenFromProvider.getToken();

		assertThat(randomCsrfToken1).isNotEqualTo(randomCsrfToken2);
		assertThat(token1.matches(randomCsrfToken1)).isTrue();
		assertThat(token1.matches(randomCsrfToken2)).isTrue();
		assertThat(tokenFromProvider.matches(randomCsrfToken1)).isTrue();
		assertThat(tokenFromProvider.matches(randomCsrfToken2)).isTrue();
	}
}
