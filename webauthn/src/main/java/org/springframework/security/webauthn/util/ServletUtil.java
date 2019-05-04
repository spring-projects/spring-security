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

package org.springframework.security.webauthn.util;


import com.webauthn4j.data.client.Origin;

import javax.servlet.ServletRequest;

/**
 * Internal utility to handle servlet
 *
 * @author Yoshikazu Nojima
 */
public class ServletUtil {

	private ServletUtil() {
	}

	/**
	 * Returns {@link Origin} corresponding {@link ServletRequest} url
	 *
	 * @param request http servlet request
	 * @return the {@link Origin}
	 */
	public static Origin getOrigin(ServletRequest request) {
		return new Origin(request.getScheme(), request.getServerName(), request.getServerPort());
	}
}
