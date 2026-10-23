/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.server.csrf;

import java.io.Serial;

/**
 * Thrown by {@link CrossOriginProtectionWebFilter} when a request that requires CSRF
 * protection is reported by the browser as coming from another origin.
 *
 * @author Scott Murphy Heiberg
 * @since 7.2
 */
public class CrossOriginRequestException extends CsrfException {

	@Serial
	private static final long serialVersionUID = 3685569093763849271L;

	/**
	 * Creates a new instance.
	 * @param message the detail message, saying how the request was found to come from
	 * another origin
	 */
	public CrossOriginRequestException(String message) {
		super(message);
	}

}
