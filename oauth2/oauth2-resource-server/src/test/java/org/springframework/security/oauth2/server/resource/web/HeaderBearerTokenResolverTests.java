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

package org.springframework.security.oauth2.server.resource.web;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link HeaderBearerTokenResolver}
 *
 * @author Elena Felder
 */
public class HeaderBearerTokenResolverTests {

	private static final String TEST_TOKEN = "test-token";

	private static final String CORRECT_HEADER = "jwt-assertion";

	private HeaderBearerTokenResolver resolver = new HeaderBearerTokenResolver(CORRECT_HEADER);

	@Test
	public void constructorWhenHeaderNullThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new HeaderBearerTokenResolver(null))
				.withMessage("header cannot be empty");
		// @formatter:on
	}

	@Test
	public void constructorWhenHeaderEmptyThenThrowIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new HeaderBearerTokenResolver(""))
				.withMessage("header cannot be empty");
		// @formatter:on
	}

	@Test
	public void resolveWhenTokenPresentThenTokenIsResolved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader(CORRECT_HEADER, TEST_TOKEN);
		assertThat(this.resolver.resolve(request)).isEqualTo(TEST_TOKEN);
	}

	@Test
	public void resolveWhenTokenNotPresentThenTokenIsNotResolved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		assertThat(this.resolver.resolve(request)).isNull();
	}

}
