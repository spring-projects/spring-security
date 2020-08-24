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

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.header.HeaderWriter;
import org.springframework.util.Assert;

/**
 * A {@link HeaderWriter} that delegates to several other {@link HeaderWriter}s.
 *
 * @author Ankur Pathak
 * @since 5.2
 */
public class CompositeHeaderWriter implements HeaderWriter {

	private final List<HeaderWriter> headerWriters;

	/**
	 * Creates a new instance.
	 * @param headerWriters the {@link HeaderWriter} instances to write out headers to the
	 * {@link HttpServletResponse}.
	 */
	public CompositeHeaderWriter(List<HeaderWriter> headerWriters) {
		Assert.notEmpty(headerWriters, "headerWriters cannot be empty");
		this.headerWriters = headerWriters;
	}

	@Override
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		this.headerWriters.forEach((headerWriter) -> headerWriter.writeHeaders(request, response));
	}

}
