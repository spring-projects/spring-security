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
package org.springframework.security.web.authentication.www;

import javax.servlet.http.HttpServletRequest;

/**
 * This class targets to parse Authentication type from `Authorization` HTTP header.
 * <br>
 * Supported `Authorization` header syntax:
 * <pre>
 * Authorization: &#60;type&#62; &#60;credentials&#62;
 * </pre>
 *
 * @author Sergey Bespalov
 *
 */
public class AuthenticationTypeParser {

	public static final String AUTHORIZATION_HEADER_NAME = "Authorization";

	public AuthenticationType parseAuthenticationType(HttpServletRequest request) {
		String header = request.getHeader(AUTHORIZATION_HEADER_NAME);
		if (header == null) {
			return null;
		}

		header = header.trim();
		String authenticationType = header.substring(0, header.indexOf(" ") + 1);

		return new AuthenticationType(authenticationType.trim());
	}

}
