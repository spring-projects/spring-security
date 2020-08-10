/*
 * Copyright 2002-2017 the original author or authors.
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
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareOnlyThisForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.util.ReflectionUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 *
 */
@RunWith(PowerMockRunner.class)
@PrepareOnlyThisForTest(ReflectionUtils.class)
public class CacheControlHeadersWriterTests {

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private CacheControlHeadersWriter writer;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.writer = new CacheControlHeadersWriter();
	}

	@Test
	public void writeHeaders() {
		this.writer.writeHeaders(this.request, this.response);

		assertThat(this.response.getHeaderNames().size()).isEqualTo(3);
		assertThat(this.response.getHeaderValues("Cache-Control"))
				.containsOnly("no-cache, no-store, max-age=0, must-revalidate");
		assertThat(this.response.getHeaderValues("Pragma")).containsOnly("no-cache");
		assertThat(this.response.getHeaderValues("Expires")).containsOnly("0");
	}

	// gh-2953
	@Test
	public void writeHeadersDisabledIfCacheControl() {
		this.response.setHeader("Cache-Control", "max-age: 123");

		this.writer.writeHeaders(this.request, this.response);

		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeaderValues("Cache-Control")).containsOnly("max-age: 123");
		assertThat(this.response.getHeaderValue("Pragma")).isNull();
		assertThat(this.response.getHeaderValue("Expires")).isNull();
	}

	@Test
	public void writeHeadersDisabledIfPragma() {
		this.response.setHeader("Pragma", "mock");

		this.writer.writeHeaders(this.request, this.response);

		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeaderValues("Pragma")).containsOnly("mock");
		assertThat(this.response.getHeaderValue("Expires")).isNull();
		assertThat(this.response.getHeaderValue("Cache-Control")).isNull();
	}

	@Test
	public void writeHeadersDisabledIfExpires() {
		this.response.setHeader("Expires", "mock");

		this.writer.writeHeaders(this.request, this.response);

		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeaderValues("Expires")).containsOnly("mock");
		assertThat(this.response.getHeaderValue("Cache-Control")).isNull();
		assertThat(this.response.getHeaderValue("Pragma")).isNull();
	}

	@Test
	// gh-5534
	public void writeHeadersDisabledIfNotModified() {
		this.response.setStatus(HttpStatus.NOT_MODIFIED.value());

		this.writer.writeHeaders(this.request, this.response);

		assertThat(this.response.getHeaderNames()).isEmpty();
	}

}
