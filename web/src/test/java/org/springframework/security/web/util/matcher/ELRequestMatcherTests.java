/*
 * Copyright 2010-2016 the original author or authors.
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

package org.springframework.security.web.util.matcher;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Mike Wiesner
 * @since 3.0.2
 */
public class ELRequestMatcherTests {

	@Test
	public void testHasIpAddressTrue() {
		ELRequestMatcher requestMatcher = new ELRequestMatcher("hasIpAddress('1.1.1.1')");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRemoteAddr("1.1.1.1");

		assertThat(requestMatcher.matches(request)).isTrue();
	}

	@Test
	public void testHasIpAddressFalse() {
		ELRequestMatcher requestMatcher = new ELRequestMatcher("hasIpAddress('1.1.1.1')");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRemoteAddr("1.1.1.2");

		assertThat(requestMatcher.matches(request)).isFalse();
	}

	@Test
	public void testHasHeaderTrue() {
		ELRequestMatcher requestMatcher = new ELRequestMatcher("hasHeader('User-Agent','MSIE')");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("User-Agent", "MSIE");

		assertThat(requestMatcher.matches(request)).isTrue();
	}

	@Test
	public void testHasHeaderTwoEntries() {
		ELRequestMatcher requestMatcher = new ELRequestMatcher(
				"hasHeader('User-Agent','MSIE') or hasHeader('User-Agent','Mozilla')");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("User-Agent", "MSIE");

		assertThat(requestMatcher.matches(request)).isTrue();

		request = new MockHttpServletRequest();
		request.addHeader("User-Agent", "Mozilla");

		assertThat(requestMatcher.matches(request)).isTrue();

	}

	@Test
	public void testHasHeaderFalse() {
		ELRequestMatcher requestMatcher = new ELRequestMatcher("hasHeader('User-Agent','MSIE')");
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("User-Agent", "wrong");

		assertThat(requestMatcher.matches(request)).isFalse();
	}

	@Test
	public void testHasHeaderNull() {
		ELRequestMatcher requestMatcher = new ELRequestMatcher("hasHeader('User-Agent','MSIE')");
		MockHttpServletRequest request = new MockHttpServletRequest();

		assertThat(requestMatcher.matches(request)).isFalse();
	}

	@Test
	public void toStringThenFormatted() {
		ELRequestMatcher requestMatcher = new ELRequestMatcher("hasHeader('User-Agent','MSIE')");
		assertThat(requestMatcher.toString()).isEqualTo("EL [el=\"hasHeader('User-Agent','MSIE')\"]");
	}

}
