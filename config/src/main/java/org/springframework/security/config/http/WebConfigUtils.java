/*
 * Copyright 2002-2012 the original author or authors.
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

package org.springframework.security.config.http;

import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.StringUtils;

/**
 * Utility methods used internally by the Spring Security http namespace configuration
 * code.
 *
 * @author Luke Taylor
 * @author Ben Alex
 */
final class WebConfigUtils {

	private WebConfigUtils() {
	}

	static int countNonEmpty(String[] objects) {
		int nonNulls = 0;
		for (String object : objects) {
			if (StringUtils.hasText(object)) {
				nonNulls++;
			}
		}
		return nonNulls;
	}

	/**
	 * Checks the value of an XML attribute which represents a redirect URL. If not empty
	 * or starting with "$" (potential placeholder), or starting with "#" (potential
	 * SpEL), "/" or "http" it will raise an error.
	 */
	static void validateHttpRedirect(String url, ParserContext pc, Object source) {
		if (!StringUtils.hasText(url) || UrlUtils.isValidRedirectUrl(url) || url.startsWith("$")
				|| url.startsWith("#")) {
			return;
		}
		pc.getReaderContext().warning(url + " is not a valid redirect URL (must start with '/' or http(s))", source);
	}

}
