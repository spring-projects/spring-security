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

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 *
 */
public class XContentTypeOptionsHeaderWriterTests {

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private XContentTypeOptionsHeaderWriter writer;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.writer = new XContentTypeOptionsHeaderWriter();
	}

	@Test
	public void writeHeaders() {
		this.writer.writeHeaders(this.request, this.response);

		assertThat(this.response.getHeaderNames()).hasSize(1);
		assertThat(this.response.getHeaderValues("X-Content-Type-Options")).containsExactly("nosniff");
	}

}
