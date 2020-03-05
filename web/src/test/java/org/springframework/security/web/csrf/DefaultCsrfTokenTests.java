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
 * @author Rob Winch
 *
 */
public class DefaultCsrfTokenTests {
	private final String headerName = "headerName";
	private final String parameterName = "parameterName";
	private final String tokenValue = "tokenValue";

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullHeaderName() {
		new DefaultCsrfToken(null, parameterName, tokenValue);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEmptyHeaderName() {
		new DefaultCsrfToken("", parameterName, tokenValue);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullParameterName() {
		new DefaultCsrfToken(headerName, null, tokenValue);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEmptyParameterName() {
		new DefaultCsrfToken(headerName, "", tokenValue);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullTokenValue() {
		new DefaultCsrfToken(headerName, parameterName, null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEmptyTokenValue() {
		new DefaultCsrfToken(headerName, parameterName, "");
	}

	@Test
	public void matchesTokenValue() {
		String tokenStr = "123456";
		DefaultCsrfToken token = new DefaultCsrfToken(headerName, parameterName, tokenStr);
		String csrfToken = token.getToken();
		String csrfToken2 = token.getToken();

		assertThat(token.getToken()).isEqualTo(csrfToken);
		assertThat(token.getToken()).isEqualTo(csrfToken2);
		assertThat(csrfToken).isEqualTo(csrfToken2);
		assertThat(token.matches(csrfToken)).isTrue();
		assertThat(token.matches(csrfToken2)).isTrue();
	}

	@Test
	public void notMatchesTokenValue() {
		DefaultCsrfToken token1 = new DefaultCsrfToken(headerName, parameterName, "token1");
		DefaultCsrfToken token2 = new DefaultCsrfToken(headerName, parameterName, "token2");
		String csrfToken1 = token1.getToken();
		String csrfToken2 = token2.getToken();

		assertThat(csrfToken1).isNotEqualTo(csrfToken2);
		assertThat(token1.matches(csrfToken2)).isFalse();
		assertThat(token2.matches(csrfToken1)).isFalse();
	}
}
