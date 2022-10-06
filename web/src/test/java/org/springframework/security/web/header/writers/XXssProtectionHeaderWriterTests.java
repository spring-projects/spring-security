/*
 * Copyright 2002-2022 the original author or authors.
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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Rob Winch
 * @author Ankur Pathak
 * @author Daniel Garnier-Moiroux
 *
 */
public class XXssProtectionHeaderWriterTests {

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private XXssProtectionHeaderWriter writer;

	private static final String XSS_PROTECTION_HEADER = "X-XSS-Protection";

	@BeforeEach
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.writer = new XXssProtectionHeaderWriter();
	}

	@Test
	public void writeHeaders() {
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeaderValues("X-XSS-Protection")).containsOnly("0");
	}

	@Test
	public void writeHeaderWhenNotPresent() {
		String value = new String("value");
		this.response.setHeader(XSS_PROTECTION_HEADER, value);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeader(XSS_PROTECTION_HEADER)).isSameAs(value);
	}

	@Test
	void writeHeaderWhenDisabled() {
		this.writer.setHeaderValue(XXssProtectionHeaderWriter.HeaderValue.DISABLED);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeaderValues("X-XSS-Protection")).containsOnly("0");
	}

	@Test
	void writeHeaderWhenEnabled() {
		this.writer.setHeaderValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeaderValues("X-XSS-Protection")).containsOnly("1");
	}

	@Test
	void writeHeaderWhenEnabledModeBlock() {
		this.writer.setHeaderValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeaderValues("X-XSS-Protection")).containsOnly("1; mode=block");
	}

	@Test
	public void setHeaderValueNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.writer.setHeaderValue(null))
				.withMessage("headerValue cannot be null");
	}

}
