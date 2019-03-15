/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.authentication.encoding;

import java.util.Locale;

/**
 * <p>
 * Plaintext implementation of PasswordEncoder.
 * </p>
 * <P>
 * As callers may wish to extract the password and salts separately from the encoded
 * password, the salt must not contain reserved characters (specifically '{' and '}').
 * </p>
 *
 * @author colin sampaleanu
 * @author Ben Alex
 * @deprecated This class will be removed in Spring Security 5. For passivity switch to
 * {@link org.springframework.security.crypto.password.NoOpPasswordEncoder}.
 */
@Deprecated
public class PlaintextPasswordEncoder extends BasePasswordEncoder {
	// ~ Instance fields
	// ================================================================================================

	private boolean ignorePasswordCase = false;

	// ~ Methods
	// ========================================================================================================

	public String encodePassword(String rawPass, Object salt) {
		return mergePasswordAndSalt(rawPass, salt, true);
	}

	public boolean isIgnorePasswordCase() {
		return ignorePasswordCase;
	}

	public boolean isPasswordValid(String encPass, String rawPass, Object salt) {
		String pass1 = encPass + "";

		// Strict delimiters is false because pass2 never persisted anywhere
		// and we want to avoid unnecessary exceptions as a result (the
		// authentication will fail as the encodePassword never allows them)
		String pass2 = mergePasswordAndSalt(rawPass, salt, false);

		if (ignorePasswordCase) {
			// Note: per String javadoc to get correct results for Locale insensitive, use
			// English
			pass1 = pass1.toLowerCase(Locale.ENGLISH);
			pass2 = pass2.toLowerCase(Locale.ENGLISH);
		}
		return PasswordEncoderUtils.equals(pass1, pass2);
	}

	/**
	 * Demerges the previously {@link #encodePassword(String, Object)}<code>String</code>.
	 * <P>
	 * The resulting array is guaranteed to always contain two elements. The first is the
	 * password, and the second is the salt.
	 * </p>
	 * <P>
	 * Throws an exception if <code>null</code> or an empty <code>String</code> is passed
	 * to the method.
	 * </p>
	 *
	 * @param password from {@link #encodePassword(String, Object)}
	 *
	 * @return an array containing the password and salt
	 */
	public String[] obtainPasswordAndSalt(String password) {
		return demergePasswordAndSalt(password);
	}

	/**
	 * Indicates whether the password comparison is case sensitive.
	 * <P>
	 * Defaults to <code>false</code>, meaning an exact case match is required.
	 * </p>
	 *
	 * @param ignorePasswordCase set to <code>true</code> for less stringent comparison
	 */
	public void setIgnorePasswordCase(boolean ignorePasswordCase) {
		this.ignorePasswordCase = ignorePasswordCase;
	}
}
