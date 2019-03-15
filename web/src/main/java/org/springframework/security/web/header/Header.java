/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.header;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.springframework.util.Assert;

/**
 * Represents a Header to be added to the {@link HttpServletResponse}
 */
public final class Header {

	private final String headerName;
	private final List<String> headerValues;

	/**
	 * Creates a new instance
	 * @param headerName the name of the header
	 * @param headerValues the values of the header
	 */
	public Header(String headerName, String... headerValues) {
		Assert.hasText(headerName, "headerName is required");
		Assert.notEmpty(headerValues, "headerValues cannot be null or empty");
		Assert.noNullElements(headerValues, "headerValues cannot contain null values");
		this.headerName = headerName;
		this.headerValues = Arrays.asList(headerValues);
	}

	/**
	 * Gets the name of the header. Cannot be <code>null</code>.
	 * @return the name of the header.
	 */
	public String getName() {
		return this.headerName;
	}

	/**
	 * Gets the values of the header. Cannot be null, empty, or contain null values.
	 *
	 * @return the values of the header
	 */
	public List<String> getValues() {
		return this.headerValues;
	}

	public int hashCode() {
		return headerName.hashCode() + headerValues.hashCode();
	}

	public String toString() {
		return "Header [name: " + headerName + ", values: " + headerValues + "]";
	}
}
