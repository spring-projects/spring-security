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
package org.springframework.security.web.header.writers.frameoptions;

import javax.servlet.http.HttpServletRequest;

/**
 * Strategy interfaces used by the {@code FrameOptionsHeaderWriter} to determine the
 * actual value to use for the X-Frame-Options header when using the ALLOW-FROM directive.
 *
 * @author Marten Deinum
 * @since 3.2
 * @deprecated ALLOW-FROM is an obsolete directive that no longer works in modern browsers. Instead use
 * Content-Security-Policy with the
 * <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors">frame-ancestors</a>
 * directive.
 */
@Deprecated
public interface AllowFromStrategy {

	/**
	 * Gets the value for ALLOW-FROM excluding the ALLOW-FROM. For example, the result
	 * might be "https://example.com/".
	 *
	 * @param request the {@link HttpServletRequest}
	 * @return the value for ALLOW-FROM or null if no header should be added for this
	 * request.
	 */
	String getAllowFromValue(HttpServletRequest request);
}
