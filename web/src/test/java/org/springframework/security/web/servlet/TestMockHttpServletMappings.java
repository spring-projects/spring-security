/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.web.servlet;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.MappingMatch;

import org.springframework.mock.web.MockHttpServletMapping;

public final class TestMockHttpServletMappings {

	private TestMockHttpServletMappings() {

	}

	public static MockHttpServletMapping extension(HttpServletRequest request, String extension) {
		String uri = request.getRequestURI();
		String matchValue = uri.substring(0, uri.lastIndexOf(extension));
		return new MockHttpServletMapping(matchValue, "*" + extension, "extension", MappingMatch.EXTENSION);
	}

	public static MockHttpServletMapping path(HttpServletRequest request, String path) {
		String uri = request.getRequestURI();
		String matchValue = uri.substring(path.length());
		return new MockHttpServletMapping(matchValue, path + "/*", "path", MappingMatch.PATH);
	}

	public static MockHttpServletMapping defaultMapping() {
		return new MockHttpServletMapping("", "/", "default", MappingMatch.DEFAULT);
	}

}
