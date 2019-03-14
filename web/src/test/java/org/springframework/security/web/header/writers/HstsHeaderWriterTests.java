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
package org.springframework.security.web.header.writers;

import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @author Ankur Pathak
 *
 */
public class HstsHeaderWriterTests {
	private MockHttpServletRequest request;
	private MockHttpServletResponse response;

	private HstsHeaderWriter writer;

	private static final String HSTS_HEADER_NAME = "Strict-Transport-Security";

	@Before
	public void setup() {
		request = new MockHttpServletRequest();
		request.setSecure(true);
		response = new MockHttpServletResponse();

		writer = new HstsHeaderWriter();
	}

	@Test
	public void allArgsCustomConstructorWriteHeaders() {
		request.setSecure(false);
		writer = new HstsHeaderWriter(AnyRequestMatcher.INSTANCE, 15768000, false);

		writer.writeHeaders(request, response);

		assertThat(response.getHeaderNames()).hasSize(1);
		assertThat(response.getHeader("Strict-Transport-Security")).isEqualTo(
				"max-age=15768000");
	}

	@Test
	public void maxAgeAndIncludeSubdomainsCustomConstructorWriteHeaders() {
		request.setSecure(false);
		writer = new HstsHeaderWriter(AnyRequestMatcher.INSTANCE, 15768000, false);

		writer.writeHeaders(request, response);

		assertThat(response.getHeaderNames()).hasSize(1);
		assertThat(response.getHeader("Strict-Transport-Security")).isEqualTo(
				"max-age=15768000");
	}

	@Test
	public void maxAgeCustomConstructorWriteHeaders() {
		writer = new HstsHeaderWriter(15768000);

		writer.writeHeaders(request, response);

		assertThat(response.getHeaderNames()).hasSize(1);
		assertThat(response.getHeader("Strict-Transport-Security")).isEqualTo(
				"max-age=15768000 ; includeSubDomains");
	}

	@Test
	public void includeSubDomainsCustomConstructorWriteHeaders() {
		writer = new HstsHeaderWriter(false);

		writer.writeHeaders(request, response);

		assertThat(response.getHeaderNames()).hasSize(1);
		assertThat(response.getHeader("Strict-Transport-Security")).isEqualTo(
				"max-age=31536000");
	}

	@Test
	public void writeHeadersDefaultValues() {
		writer.writeHeaders(request, response);

		assertThat(response.getHeaderNames()).hasSize(1);
		assertThat(response.getHeader("Strict-Transport-Security")).isEqualTo(
				"max-age=31536000 ; includeSubDomains");
	}

	@Test
	public void writeHeadersIncludeSubDomainsFalse() {
		writer.setIncludeSubDomains(false);

		writer.writeHeaders(request, response);

		assertThat(response.getHeaderNames()).hasSize(1);
		assertThat(response.getHeader("Strict-Transport-Security")).isEqualTo(
				"max-age=31536000");
	}

	@Test
	public void writeHeadersCustomMaxAgeInSeconds() {
		writer.setMaxAgeInSeconds(1);

		writer.writeHeaders(request, response);

		assertThat(response.getHeaderNames()).hasSize(1);
		assertThat(response.getHeader("Strict-Transport-Security")).isEqualTo(
				"max-age=1 ; includeSubDomains");
	}

	@Test
	public void writeHeadersInsecureRequestDoesNotWriteHeader() {
		request.setSecure(false);

		writer.writeHeaders(request, response);

		assertThat(response.getHeaderNames().isEmpty()).isTrue();
	}

	@Test
	public void writeHeadersAnyRequestMatcher() {
		writer.setRequestMatcher(AnyRequestMatcher.INSTANCE);
		request.setSecure(false);

		writer.writeHeaders(request, response);

		assertThat(response.getHeaderNames()).hasSize(1);
		assertThat(response.getHeader("Strict-Transport-Security")).isEqualTo(
				"max-age=31536000 ; includeSubDomains");
	}

	@Test(expected = IllegalArgumentException.class)
	public void setMaxAgeInSecondsToNegative() {
		writer.setMaxAgeInSeconds(-1);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setRequestMatcherToNull() {
		writer.setRequestMatcher(null);
	}

	@Test
	public void writeHeaderWhenNotPresent() {
		String value = new String("value");
		this.response.setHeader(HSTS_HEADER_NAME, value);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeader(HSTS_HEADER_NAME)).isSameAs(value);
	}
}
