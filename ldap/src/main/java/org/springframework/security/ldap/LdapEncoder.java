/*
 * Copyright 2005-2024 the original author or authors.
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

package org.springframework.security.ldap;

/**
 * Helper class to encode and decode ldap names and values.
 *
 * <p>
 * NOTE: This is a copy from Spring LDAP so that both Spring LDAP 1.x and 2.x can be
 * supported without reflection.
 * </p>
 *
 * @author Adam Skogman
 * @author Mattias Hellborg Arthursson
 */
final class LdapEncoder {

	private static final String[] FILTER_ESCAPE_TABLE = new String['\\' + 1];

	static {
		// fill with char itself
		for (char c = 0; c < FILTER_ESCAPE_TABLE.length; c++) {
			FILTER_ESCAPE_TABLE[c] = String.valueOf(c);
		}
		// escapes (RFC2254)
		FILTER_ESCAPE_TABLE['*'] = "\\2a";
		FILTER_ESCAPE_TABLE['('] = "\\28";
		FILTER_ESCAPE_TABLE[')'] = "\\29";
		FILTER_ESCAPE_TABLE['\\'] = "\\5c";
		FILTER_ESCAPE_TABLE[0] = "\\00";
	}

	/**
	 * All static methods - not to be instantiated.
	 */
	private LdapEncoder() {
	}

	/**
	 * Escape a value for use in a filter.
	 * @param value the value to escape.
	 * @return a properly escaped representation of the supplied value.
	 */
	static String filterEncode(String value) {
		if (value == null) {
			return null;
		}
		StringBuilder encodedValue = new StringBuilder(value.length() * 2);
		int length = value.length();
		for (int i = 0; i < length; i++) {
			char ch = value.charAt(i);
			encodedValue.append((ch < FILTER_ESCAPE_TABLE.length) ? FILTER_ESCAPE_TABLE[ch] : ch);
		}
		return encodedValue.toString();
	}

}
