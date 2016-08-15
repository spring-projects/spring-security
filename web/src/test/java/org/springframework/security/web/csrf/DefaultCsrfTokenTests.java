/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.csrf;

import org.junit.Test;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 *
 */
public class DefaultCsrfTokenTests {
	private final String headerName = "headerName";
	private final String parameterName = "parameterName";

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullHeaderName() {
		new DefaultCsrfToken(null, parameterName);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEmptyHeaderName() {
		new DefaultCsrfToken("", parameterName);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullParameterName() {
		new DefaultCsrfToken(headerName, null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEmptyParameterName() {
		new DefaultCsrfToken(headerName, "");
	}

	@Test
	public void testIsValid() {
		DefaultCsrfToken token = new DefaultCsrfToken(headerName, parameterName);

		String value1 = token.getToken();
		assertThat(value1).isNotEmpty();
		String value2 = token.getToken();
		assertThat(value2).isNotEmpty();

		assertThat(value1).doesNotMatch(value2);

		assertThat(token.isValid(value1)).isTrue();
		assertThat(token.isValid(value2)).isTrue();
		assertThat(token.isValid(value2.replaceAll("^.{10}","INVALID000"))).isFalse();
	}

}
