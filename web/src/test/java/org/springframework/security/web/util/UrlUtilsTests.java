/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for {@link UrlUtils}
 *
 * @author Luke Taylor
 */
public class UrlUtilsTests {

	@ParameterizedTest
	@CsvSource(textBlock = """
			 , https://example.com,
			'', https://example.com,
			/, https://example.com/,
			requestUri, https://example.com/requestUri,
			/requestUri, https://example.com/requestUri,
			requestUri/, https://example.com/requestUri/,
			/requestUri/, https://example.com/requestUri/,
			//requestUri//, https://example.com//requestUri//
			""")
	public void buildFullRequestUrl(String requestUri, String expected) {

		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setScheme("https");
		request.setServerName("example.com");
		request.setServerPort(443);
		assertThat(UrlUtils.buildFullRequestUrl(request)).isEqualTo(expected);
	}

	@Test
	public void absoluteUrlsAreMatchedAsAbsolute() {
		assertThat(UrlUtils.isAbsoluteUrl("https://something/")).isTrue();
		assertThat(UrlUtils.isAbsoluteUrl("http1://something/")).isTrue();
		assertThat(UrlUtils.isAbsoluteUrl("HTTP://something/")).isTrue();
		assertThat(UrlUtils.isAbsoluteUrl("https://something/")).isTrue();
		assertThat(UrlUtils.isAbsoluteUrl("a://something/")).isTrue();
		assertThat(UrlUtils.isAbsoluteUrl("zz+zz.zz-zz://something/")).isTrue();
	}

	@Test
	public void isAbsoluteUrlWhenNullThenFalse() {
		assertThat(UrlUtils.isAbsoluteUrl(null)).isFalse();
	}

	@Test
	public void isAbsoluteUrlWhenEmptyThenFalse() {
		assertThat(UrlUtils.isAbsoluteUrl("")).isFalse();
	}

	@Test
	public void isValidRedirectUrlWhenNullThenFalse() {
		assertThat(UrlUtils.isValidRedirectUrl(null)).isFalse();
	}

	@Test
	public void isValidRedirectUrlWhenEmptyThenFalse() {
		assertThat(UrlUtils.isValidRedirectUrl("")).isFalse();
	}

}
