/*
 * Copyright 2005-2010 the original author or authors.
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

package org.springframework.security.ldap.authentication;

import org.springframework.ldap.BadLdapGrammarException;

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

	private static final int HEX = 16;
	private static String[] NAME_ESCAPE_TABLE = new String[96];

	private static String[] FILTER_ESCAPE_TABLE = new String['\\' + 1];

	static {

		// Name encoding table -------------------------------------

		// all below 0x20 (control chars)
		for (char c = 0; c < ' '; c++) {
			NAME_ESCAPE_TABLE[c] = "\\" + toTwoCharHex(c);
		}

		NAME_ESCAPE_TABLE['#'] = "\\#";
		NAME_ESCAPE_TABLE[','] = "\\,";
		NAME_ESCAPE_TABLE[';'] = "\\;";
		NAME_ESCAPE_TABLE['='] = "\\=";
		NAME_ESCAPE_TABLE['+'] = "\\+";
		NAME_ESCAPE_TABLE['<'] = "\\<";
		NAME_ESCAPE_TABLE['>'] = "\\>";
		NAME_ESCAPE_TABLE['\"'] = "\\\"";
		NAME_ESCAPE_TABLE['\\'] = "\\\\";

		// Filter encoding table -------------------------------------

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

	protected static String toTwoCharHex(char c) {

		String raw = Integer.toHexString(c).toUpperCase();

		if (raw.length() > 1) {
			return raw;
		}
		else {
			return "0" + raw;
		}
	}

	/**
	 * Escape a value for use in a filter.
	 *
	 * @param value the value to escape.
	 * @return a properly escaped representation of the supplied value.
	 */
	public static String filterEncode(String value) {

		if (value == null) {
			return null;
		}

		// make buffer roomy
		StringBuilder encodedValue = new StringBuilder(value.length() * 2);

		int length = value.length();

		for (int i = 0; i < length; i++) {

			char c = value.charAt(i);

			if (c < FILTER_ESCAPE_TABLE.length) {
				encodedValue.append(FILTER_ESCAPE_TABLE[c]);
			}
			else {
				// default: add the char
				encodedValue.append(c);
			}
		}

		return encodedValue.toString();
	}

	/**
	 * LDAP Encodes a value for use with a DN. Escapes for LDAP, not JNDI!
	 *
	 * <br/>
	 * Escapes:<br/>
	 * ' ' [space] - "\ " [if first or last] <br/>
	 * '#' [hash] - "\#" <br/>
	 * ',' [comma] - "\," <br/>
	 * ';' [semicolon] - "\;" <br/>
	 * '= [equals] - "\=" <br/>
	 * '+' [plus] - "\+" <br/>
	 * '&lt;' [less than] - "\&lt;" <br/>
	 * '&gt;' [greater than] - "\&gt;" <br/>
	 * '"' [double quote] - "\"" <br/>
	 * '\' [backslash] - "\\" <br/>
	 *
	 * @param value the value to escape.
	 * @return The escaped value.
	 */
	public static String nameEncode(String value) {

		if (value == null) {
			return null;
		}

		// make buffer roomy
		StringBuilder encodedValue = new StringBuilder(value.length() * 2);

		int length = value.length();
		int last = length - 1;

		for (int i = 0; i < length; i++) {

			char c = value.charAt(i);

			// space first or last
			if (c == ' ' && (i == 0 || i == last)) {
				encodedValue.append("\\ ");
				continue;
			}

			if (c < NAME_ESCAPE_TABLE.length) {
				// check in table for escapes
				String esc = NAME_ESCAPE_TABLE[c];

				if (esc != null) {
					encodedValue.append(esc);
					continue;
				}
			}

			// default: add the char
			encodedValue.append(c);
		}

		return encodedValue.toString();

	}

	/**
	 * Decodes a value. Converts escaped chars to ordinary chars.
	 *
	 * @param value Trimmed value, so no leading an trailing blanks, except an escaped
	 * space last.
	 * @return The decoded value as a string.
	 * @throws BadLdapGrammarException
	 */
	static public String nameDecode(String value) throws BadLdapGrammarException {

		if (value == null) {
			return null;
		}

		// make buffer same size
		StringBuilder decoded = new StringBuilder(value.length());

		int i = 0;
		while (i < value.length()) {
			char currentChar = value.charAt(i);
			if (currentChar == '\\') {
				if (value.length() <= i + 1) {
					// Ending with a single backslash is not allowed
					throw new BadLdapGrammarException(
							"Unexpected end of value " + "unterminated '\\'");
				}
				else {
					char nextChar = value.charAt(i + 1);
					if (nextChar == ',' || nextChar == '=' || nextChar == '+'
							|| nextChar == '<' || nextChar == '>' || nextChar == '#'
							|| nextChar == ';' || nextChar == '\\' || nextChar == '\"'
							|| nextChar == ' ') {
						// Normal backslash escape
						decoded.append(nextChar);
						i += 2;
					}
					else {
						if (value.length() <= i + 2) {
							throw new BadLdapGrammarException("Unexpected end of value "
									+ "expected special or hex, found '" + nextChar
									+ "'");
						}
						else {
							// This should be a hex value
							String hexString = "" + nextChar + value.charAt(i + 2);
							decoded.append((char) Integer.parseInt(hexString, HEX));
							i += 3;
						}
					}
				}
			}
			else {
				// This character wasn't escaped - just append it
				decoded.append(currentChar);
				i++;
			}
		}

		return decoded.toString();

	}
}
