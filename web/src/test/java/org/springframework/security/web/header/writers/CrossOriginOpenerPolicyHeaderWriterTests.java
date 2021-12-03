/*
 * Copyright 2002-2021 the original author or authors.
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

class CrossOriginOpenerPolicyHeaderWriterTests {

	private static final String OPENER_HEADER_NAME = "Cross-Origin-Opener-Policy";

	private CrossOriginOpenerPolicyHeaderWriter writer;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	@BeforeEach
	void setup() {
		this.writer = new CrossOriginOpenerPolicyHeaderWriter();
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
	}

	@Test
	void setOpenerPolicyWhenNullOpenerPolicyThenThrowsIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.writer.setPolicy(null))
				.withMessage("openerPolicy cannot be null");
	}

	@Test
	void writeHeadersWhenDefaultValuesThenDontWriteHeaders() {
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(0);
	}

	@Test
	void writeHeadersWhenResponseHeaderExistsThenDontOverride() {
		this.response.addHeader(OPENER_HEADER_NAME, "same-origin");
		this.writer.setPolicy(CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy.SAME_ORIGIN_ALLOW_POPUPS);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeader(OPENER_HEADER_NAME)).isEqualTo("same-origin");
	}

	@Test
	void writeHeadersWhenSetHeaderValuesThenWrites() {
		this.writer.setPolicy(CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy.SAME_ORIGIN_ALLOW_POPUPS);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeader(OPENER_HEADER_NAME)).isEqualTo("same-origin-allow-popups");
	}

	@Test
	void writeHeadersWhenSetOpenerPolicyThenWritesOpenerPolicy() {
		this.writer.setPolicy(CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy.SAME_ORIGIN_ALLOW_POPUPS);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader(OPENER_HEADER_NAME)).isEqualTo("same-origin-allow-popups");
	}

}
