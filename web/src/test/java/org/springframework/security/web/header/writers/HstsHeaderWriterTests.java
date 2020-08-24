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
		this.request = new MockHttpServletRequest();
		this.request.setSecure(true);
		this.response = new MockHttpServletResponse();
		this.writer = new HstsHeaderWriter();
	}

	@Test
	public void allArgsCustomConstructorWriteHeaders() {
		this.request.setSecure(false);
		this.writer = new HstsHeaderWriter(AnyRequestMatcher.INSTANCE, 15768000, false);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader("Strict-Transport-Security")).isEqualTo("max-age=15768000");
	}

	@Test
	public void maxAgeAndIncludeSubdomainsCustomConstructorWriteHeaders() {
		this.request.setSecure(false);
		this.writer = new HstsHeaderWriter(AnyRequestMatcher.INSTANCE, 15768000, false);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader("Strict-Transport-Security")).isEqualTo("max-age=15768000");
	}

	@Test
	public void maxAgeCustomConstructorWriteHeaders() {
		this.writer = new HstsHeaderWriter(15768000);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader("Strict-Transport-Security"))
				.isEqualTo("max-age=15768000 ; includeSubDomains");
	}

	@Test
	public void includeSubDomainsCustomConstructorWriteHeaders() {
		this.writer = new HstsHeaderWriter(false);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader("Strict-Transport-Security")).isEqualTo("max-age=31536000");
	}

	@Test
	public void writeHeadersDefaultValues() {
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader("Strict-Transport-Security"))
				.isEqualTo("max-age=31536000 ; includeSubDomains");
	}

	@Test
	public void writeHeadersIncludeSubDomainsFalse() {
		this.writer.setIncludeSubDomains(false);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader("Strict-Transport-Security")).isEqualTo("max-age=31536000");
	}

	@Test
	public void writeHeadersCustomMaxAgeInSeconds() {
		this.writer.setMaxAgeInSeconds(1);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader("Strict-Transport-Security")).isEqualTo("max-age=1 ; includeSubDomains");
	}

	@Test
	public void writeHeadersInsecureRequestDoesNotWriteHeader() {
		this.request.setSecure(false);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames().isEmpty()).isTrue();
	}

	@Test
	public void writeHeadersAnyRequestMatcher() {
		this.writer.setRequestMatcher(AnyRequestMatcher.INSTANCE);
		this.request.setSecure(false);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader("Strict-Transport-Security"))
				.isEqualTo("max-age=31536000 ; includeSubDomains");
	}

	@Test(expected = IllegalArgumentException.class)
	public void setMaxAgeInSecondsToNegative() {
		this.writer.setMaxAgeInSeconds(-1);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setRequestMatcherToNull() {
		this.writer.setRequestMatcher(null);
	}

	@Test
	public void writeHeaderWhenNotPresent() {
		String value = new String("value");
		this.response.setHeader(HSTS_HEADER_NAME, value);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeader(HSTS_HEADER_NAME)).isSameAs(value);
	}

}
