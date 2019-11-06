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

import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.header.Header;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.util.Assert;

/**
 * {@code HeaderWriter} implementation which writes the same {@code Header} instance.
 *
 * @author Marten Deinum
 * @author Rob Winch
 * @author Ankur Pathak
 * @since 3.2
 */
public class StaticHeadersWriter implements HeaderWriter {

	private final List<Header> headers;

	/**
	 * Creates a new instance
	 * @param headers the {@link Header} instances to use
	 */
	public StaticHeadersWriter(List<Header> headers) {
		Assert.notEmpty(headers, "headers cannot be null or empty");
		this.headers = headers;
	}

	/**
	 * Creates a new instance with a single header
	 * @param headerName the name of the header
	 * @param headerValues the values for the header
	 */
	public StaticHeadersWriter(String headerName, String... headerValues) {
		this(Collections.singletonList(new Header(headerName, headerValues)));
	}

	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		for (Header header : headers) {
			if (!response.containsHeader(header.getName())) {
				for (String value : header.getValues()) {
					response.addHeader(header.getName(), value);
				}
			}
		}
	}

	@Override
	public String toString() {
		return getClass().getName() + " [headers=" + headers + "]";
	}
}
