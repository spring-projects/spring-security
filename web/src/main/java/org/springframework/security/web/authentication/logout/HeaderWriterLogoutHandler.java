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

package org.springframework.security.web.authentication.logout;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.util.Assert;

/**
 * @author Rafiullah Hamedy
 * @since 5.2
 */
public final class HeaderWriterLogoutHandler implements LogoutHandler {

	private final HeaderWriter headerWriter;

	/**
	 * Constructs a new instance using the passed {@link HeaderWriter} implementation
	 * @param headerWriter
	 * @throws {@link IllegalArgumentException} if headerWriter is null.
	 */
	public HeaderWriterLogoutHandler(HeaderWriter headerWriter) {
		Assert.notNull(headerWriter, "headerWriter cannot be null");
		this.headerWriter = headerWriter;
	}

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		this.headerWriter.writeHeaders(request, response);
	}

}
