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

class CrossOriginEmbedderPolicyHeaderWriterTests {

	private static final String EMBEDDER_HEADER_NAME = "Cross-Origin-Embedder-Policy";

	private CrossOriginEmbedderPolicyHeaderWriter writer;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	@BeforeEach
	void setup() {
		this.writer = new CrossOriginEmbedderPolicyHeaderWriter();
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
	}

	@Test
	void setEmbedderPolicyWhenNullEmbedderPolicyThenThrowsIllegalArgument() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.writer.setPolicy(null))
				.withMessage("embedderPolicy cannot be null");
	}

	@Test
	void writeHeadersWhenDefaultValuesThenDontWriteHeaders() {
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(0);
	}

	@Test
	void writeHeadersWhenResponseHeaderExistsThenDontOverride() {
		this.response.addHeader(EMBEDDER_HEADER_NAME, "require-corp");
		this.writer.setPolicy(CrossOriginEmbedderPolicyHeaderWriter.CrossOriginEmbedderPolicy.UNSAFE_NONE);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeader(EMBEDDER_HEADER_NAME)).isEqualTo("require-corp");
	}

	@Test
	void writeHeadersWhenSetHeaderValuesThenWrites() {
		this.writer.setPolicy(CrossOriginEmbedderPolicyHeaderWriter.CrossOriginEmbedderPolicy.REQUIRE_CORP);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeader(EMBEDDER_HEADER_NAME)).isEqualTo("require-corp");
	}

	@Test
	void writeHeadersWhenSetEmbedderPolicyThenWritesEmbedderPolicy() {
		this.writer.setPolicy(CrossOriginEmbedderPolicyHeaderWriter.CrossOriginEmbedderPolicy.UNSAFE_NONE);
		this.writer.writeHeaders(this.request, this.response);
		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeader(EMBEDDER_HEADER_NAME)).isEqualTo("unsafe-none");
	}

}
