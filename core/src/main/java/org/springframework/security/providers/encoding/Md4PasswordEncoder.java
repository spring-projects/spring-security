/* Copyright 2004, 2005, 2006, 2007 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.providers.encoding;

import java.io.UnsupportedEncodingException;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

/**
 * MD4 implementation of PasswordEncoder.
 * <p>
 * If a <code>null</code> password is presented, it will be treated as an empty <code>String</code> ("") password.
 * <p>
 * As MD4 is a one-way hash, the salt can contain any characters.
 * <p>
 * <b>NOTE:</b> This password encoder is only included for backwards compatability with legacy applications, it's not
 * secure, don't use it for anything new!
 *
 * @author Alan Stewart
 */
public class Md4PasswordEncoder extends BaseDigestPasswordEncoder {

    //~ Methods ========================================================================================================

    /**
	 * Encodes the rawPass using an MD4 message digest. If a salt is specified it will be merged with the password
     * before encoding.
	 *
	 * @param rawPass The plain text password
	 * @param salt The salt to sprinkle
	 * @return Hex string of password digest (or base64 encoded string if encodeHashAsBase64 is enabled.
	 */
	public String encodePassword(String rawPass, Object salt) {
		String saltedPass = mergePasswordAndSalt(rawPass, salt, false);
		
		byte[] passBytes;

		try {
			passBytes = saltedPass.getBytes("UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("UTF-8 not supported!");
		}
		
		Md4 md4 = new Md4();
		md4.update(passBytes, 0, saltedPass.length());
		
		byte[] resBuf = md4.digest();

		if (getEncodeHashAsBase64()) {
			return new String(Base64.encodeBase64(resBuf));
		} else {
			return new String(Hex.encodeHex(resBuf));
		}
	}

	/**
	 * Takes a previously encoded password and compares it with a raw password after mixing in the salt and
     * encoding that value.
	 *
	 * @param encPass previously encoded password
	 * @param rawPass plain text password
	 * @param salt salt to mix into password
	 * @return true or false
	 */
	public boolean isPasswordValid(String encPass, String rawPass, Object salt) {
		String pass1 = "" + encPass;
		String pass2 = encodePassword(rawPass, salt);
		return pass1.equals(pass2);
	}

	public String getAlgorithm() {
		return "MD4";
	}
}