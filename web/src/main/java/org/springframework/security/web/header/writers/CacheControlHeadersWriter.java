/*
 * Copyright 2002-2018 the original author or authors.
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

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.web.header.Header;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.util.ReflectionUtils;

/**
 * Inserts headers to prevent caching if no cache control headers have been specified.
 * Specifically it adds the following headers:
 * <ul>
 * <li>Cache-Control: no-cache, no-store, max-age=0, must-revalidate</li>
 * <li>Pragma: no-cache</li>
 * <li>Expires: 0</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class CacheControlHeadersWriter implements HeaderWriter {
	private static final String EXPIRES = "Expires";
	private static final String PRAGMA = "Pragma";
	private static final String CACHE_CONTROL = "Cache-Control";

	private final Method getHeaderMethod;

	private final HeaderWriter delegate;

	/**
	 * Creates a new instance
	 */
	public CacheControlHeadersWriter() {
		this.delegate = new StaticHeadersWriter(createHeaders());
		this.getHeaderMethod = ReflectionUtils.findMethod(HttpServletResponse.class,
				"getHeader", String.class);
	}

	@Override
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		if (hasHeader(response, CACHE_CONTROL) || hasHeader(response, EXPIRES)
				|| hasHeader(response, PRAGMA) || response.getStatus() == HttpStatus.NOT_MODIFIED.value()) {
			return;
		}
		this.delegate.writeHeaders(request, response);
	}

	private boolean hasHeader(HttpServletResponse response, String headerName) {
		if (this.getHeaderMethod == null) {
			return false;
		}
		return ReflectionUtils.invokeMethod(this.getHeaderMethod, response,
				headerName) != null;
	}

	private static List<Header> createHeaders() {
		List<Header> headers = new ArrayList<>(3);
		headers.add(new Header(CACHE_CONTROL,
				"no-cache, no-store, max-age=0, must-revalidate"));
		headers.add(new Header(PRAGMA, "no-cache"));
		headers.add(new Header(EXPIRES, "0"));
		return headers;
	}
}
