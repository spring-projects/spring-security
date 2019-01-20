/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.header.writers;

import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.header.HeaderWriter;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for class {@link CompositeHeaderWriter}/.
 *
 * @author Ankur Pathak
 * @since 5.2
 */
public class CompositeHeaderWriterTests {
	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private CompositeHeaderWriter writer;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		HeaderWriter writerA = (request, response) -> {
			if (!response.containsHeader("A")) {
				response.setHeader("A", "a");
			}
		};

		HeaderWriter writerB = (request, response) -> {
			if (!response.containsHeader("B")) {
				response.setHeader("B", "b");
			}
		};
		this.writer = new CompositeHeaderWriter(Arrays.asList(writerA, writerB));
	}


	@Test
	public void doCompositeHeaderWrite(){
		this.writer.writeHeaders(request, response);
		assertThat(this.response.containsHeader("A")).isTrue();
		assertThat(this.response.containsHeader("B")).isTrue();
		assertThat(this.response.getHeader("A")).isEqualTo("a");
		assertThat(this.response.getHeader("B")).isEqualTo("b");
	}
}
