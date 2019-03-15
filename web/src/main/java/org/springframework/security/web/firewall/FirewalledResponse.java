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
package org.springframework.security.web.firewall;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.util.regex.Pattern;

/**
 * @author Luke Taylor
 */
class FirewalledResponse extends HttpServletResponseWrapper {
	private static final Pattern CR_OR_LF = Pattern.compile("\\r|\\n");

	public FirewalledResponse(HttpServletResponse response) {
		super(response);
	}

	@Override
	public void sendRedirect(String location) throws IOException {
		// TODO: implement pluggable validation, instead of simple blacklisting.
		// SEC-1790. Prevent redirects containing CRLF
		if (CR_OR_LF.matcher(location).find()) {
			throw new IllegalArgumentException(
					"Invalid characters (CR/LF) in redirect location");
		}
		super.sendRedirect(location);
	}
}
