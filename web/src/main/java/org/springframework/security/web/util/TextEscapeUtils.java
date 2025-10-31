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

package org.springframework.security.web.util;

import org.springframework.util.StringUtils;

/**
 * Internal utility for escaping characters in HTML strings.
 *
 * @author Luke Taylor
 *
 */
public abstract class TextEscapeUtils {

	public static String escapeEntities(String s) {
		if (!StringUtils.hasLength(s)) {
			return s;
		}
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < s.length(); i++) {
			char ch = s.charAt(i);
			if (ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
				sb.append(ch);
			}
			else if (ch == '<') {
				sb.append("&lt;");
			}
			else if (ch == '>') {
				sb.append("&gt;");
			}
			else if (ch == '&') {
				sb.append("&amp;");
			}
			else if (Character.isWhitespace(ch)) {
				sb.append("&#").append((int) ch).append(";");
			}
			else if (Character.isISOControl(ch)) {
				// ignore control chars
			}
			else if (Character.isHighSurrogate(ch)) {
				if (i + 1 >= s.length()) {
					// Unexpected end
					throw new IllegalArgumentException("Missing low surrogate character at end of string");
				}
				char low = s.charAt(i + 1);
				if (!Character.isLowSurrogate(low)) {
					throw new IllegalArgumentException(
							"Expected low surrogate character but found value = " + (int) low);
				}
				int codePoint = Character.toCodePoint(ch, low);
				if (Character.isDefined(codePoint)) {
					sb.append("&#").append(codePoint).append(";");
				}
				i++; // skip the next character as we have already dealt with it
			}
			else if (Character.isLowSurrogate(ch)) {
				throw new IllegalArgumentException("Unexpected low surrogate character, value = " + (int) ch);
			}
			else if (Character.isDefined(ch)) {
				sb.append("&#").append((int) ch).append(";");
			}
			// Ignore anything else
		}
		return sb.toString();
	}

}
