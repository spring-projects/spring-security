/*
 * Copyright 2002-2013 the original author or authors.
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

package org.springframework.security.web.csrf;

import java.io.Serial;

import org.springframework.security.access.AccessDeniedException;

/**
 * Thrown when an invalid or missing {@link CsrfToken} is found in the HttpServletRequest
 *
 * @author Rob Winch
 * @since 3.2
 */
public class CsrfException extends AccessDeniedException {

	@Serial
	private static final long serialVersionUID = 7802567627837252670L;

	public CsrfException(String message) {
		super(message);
	}

}
