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
package org.springframework.security.web.util;

/**
 * Internal utility for escaping characters in HTML strings.
 *
 * @author Luke Taylor
 *
 */
public abstract class TextEscapeUtils {

	public static String escapeEntities(String s) {
		if (s == null || s.length() == 0) {
			return s;
		}

		StringBuilder sb = new StringBuilder();

		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);

			if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
				sb.append(c);
			}
			else if (c == '<') {
				sb.append("&lt;");
			}
			else if (c == '>') {
				sb.append("&gt;");
			}
			else if (c == '&') {
				sb.append("&amp;");
			}
			else if (Character.isWhitespace(c)) {
				sb.append("&#").append((int) c).append(";");
			}
			else if (Character.isISOControl(c)) {
				// ignore control chars
			}
			else if (Character.isHighSurrogate(c)) {
				if (i + 1 >= s.length()) {
					// Unexpected end
					throw new IllegalArgumentException("Missing low surrogate character at end of string");
				}
				char low = s.charAt(i + 1);

				if (!Character.isLowSurrogate(low)) {
					throw new IllegalArgumentException(
							"Expected low surrogate character but found value = " + (int) low);
				}

				int codePoint = Character.toCodePoint(c, low);
				if (Character.isDefined(codePoint)) {
					sb.append("&#").append(codePoint).append(";");
				}
				i++; // skip the next character as we have already dealt with it
			}
			else if (Character.isLowSurrogate(c)) {
				throw new IllegalArgumentException("Unexpected low surrogate character, value = " + (int) c);
			}
			else if (Character.isDefined(c)) {
				sb.append("&#").append((int) c).append(";");
			}
			// Ignore anything else
		}

		return sb.toString();
	}

}
