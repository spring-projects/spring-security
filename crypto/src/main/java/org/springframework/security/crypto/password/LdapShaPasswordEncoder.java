/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.crypto.password;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.Locale;

import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;

/**
 * This {@link PasswordEncoder} is provided for legacy purposes only and is not considered
 * secure.
 *
 * A version of {@link PasswordEncoder} which supports Ldap SHA and SSHA (salted-SHA)
 * encodings. The values are base-64 encoded and have the label "{SHA}" (or "{SSHA}")
 * prepended to the encoded hash. These can be made lower-case in the encoded password, if
 * required, by setting the <tt>forceLowerCasePrefix</tt> property to true.
 *
 * Also supports plain text passwords, so can safely be used in cases when both encoded
 * and non-encoded passwords are in use or when a null implementation is required.
 *
 * @author Luke Taylor
 * @deprecated Digest based password encoding is not considered secure. Instead use an
 * adaptive one way function like BCryptPasswordEncoder, Pbkdf2PasswordEncoder, or
 * SCryptPasswordEncoder. Even better use {@link DelegatingPasswordEncoder} which supports
 * password upgrades. There are no plans to remove this support. It is deprecated to
 * indicate that this is a legacy implementation and using it is considered insecure.
 */
@Deprecated
public class LdapShaPasswordEncoder implements PasswordEncoder {

	/** The number of bytes in a SHA hash */
	private static final int SHA_LENGTH = 20;

	private static final String SSHA_PREFIX = "{SSHA}";

	private static final String SSHA_PREFIX_LC = SSHA_PREFIX.toLowerCase(Locale.ENGLISH);

	private static final String SHA_PREFIX = "{SHA}";

	private static final String SHA_PREFIX_LC = SHA_PREFIX.toLowerCase(Locale.ENGLISH);

	private BytesKeyGenerator saltGenerator;

	private boolean forceLowerCasePrefix;

	public LdapShaPasswordEncoder() {
		this(KeyGenerators.secureRandom());
	}

	public LdapShaPasswordEncoder(BytesKeyGenerator saltGenerator) {
		if (saltGenerator == null) {
			throw new IllegalArgumentException("saltGenerator cannot be null");
		}
		this.saltGenerator = saltGenerator;
	}

	private byte[] combineHashAndSalt(byte[] hash, byte[] salt) {
		if (salt == null) {
			return hash;
		}
		byte[] hashAndSalt = new byte[hash.length + salt.length];
		System.arraycopy(hash, 0, hashAndSalt, 0, hash.length);
		System.arraycopy(salt, 0, hashAndSalt, hash.length, salt.length);
		return hashAndSalt;
	}

	/**
	 * Calculates the hash of password (and salt bytes, if supplied) and returns a base64
	 * encoded concatenation of the hash and salt, prefixed with {SHA} (or {SSHA} if salt
	 * was used).
	 * @param rawPass the password to be encoded.
	 * @return the encoded password in the specified format
	 *
	 */
	@Override
	public String encode(CharSequence rawPass) {
		byte[] salt = this.saltGenerator.generateKey();
		return encode(rawPass, salt);
	}

	private String encode(CharSequence rawPassword, byte[] salt) {
		MessageDigest sha = getSha(rawPassword);
		if (salt != null) {
			sha.update(salt);
		}
		byte[] hash = combineHashAndSalt(sha.digest(), salt);
		String prefix = getPrefix(salt);
		return prefix + Utf8.decode(Base64.getEncoder().encode(hash));
	}

	private MessageDigest getSha(CharSequence rawPassword) {
		try {
			MessageDigest sha = MessageDigest.getInstance("SHA");
			sha.update(Utf8.encode(rawPassword));
			return sha;
		}
		catch (java.security.NoSuchAlgorithmException ex) {
			throw new IllegalStateException("No SHA implementation available!");
		}
	}

	private String getPrefix(byte[] salt) {
		if (salt == null || salt.length == 0) {
			return this.forceLowerCasePrefix ? SHA_PREFIX_LC : SHA_PREFIX;
		}
		return this.forceLowerCasePrefix ? SSHA_PREFIX_LC : SSHA_PREFIX;
	}

	private byte[] extractSalt(String encPass) {
		String encPassNoLabel = encPass.substring(6);
		byte[] hashAndSalt = Base64.getDecoder().decode(encPassNoLabel.getBytes());
		int saltLength = hashAndSalt.length - SHA_LENGTH;
		byte[] salt = new byte[saltLength];
		System.arraycopy(hashAndSalt, SHA_LENGTH, salt, 0, saltLength);
		return salt;
	}

	/**
	 * Checks the validity of an unencoded password against an encoded one in the form
	 * "{SSHA}sQuQF8vj8Eg2Y1hPdh3bkQhCKQBgjhQI".
	 * @param rawPassword unencoded password to be verified.
	 * @param encodedPassword the actual SSHA or SHA encoded password
	 * @return true if they match (independent of the case of the prefix).
	 */
	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		return matches((rawPassword != null) ? rawPassword.toString() : null, encodedPassword);
	}

	private boolean matches(String rawPassword, String encodedPassword) {
		String prefix = extractPrefix(encodedPassword);
		if (prefix == null) {
			return PasswordEncoderUtils.equals(encodedPassword, rawPassword);
		}
		byte[] salt = getSalt(encodedPassword, prefix);
		int startOfHash = prefix.length();
		String encodedRawPass = encode(rawPassword, salt).substring(startOfHash);
		return PasswordEncoderUtils.equals(encodedRawPass, encodedPassword.substring(startOfHash));
	}

	private byte[] getSalt(String encodedPassword, String prefix) {
		if (prefix.equals(SSHA_PREFIX) || prefix.equals(SSHA_PREFIX_LC)) {
			return extractSalt(encodedPassword);
		}
		if (!prefix.equals(SHA_PREFIX) && !prefix.equals(SHA_PREFIX_LC)) {
			throw new IllegalArgumentException("Unsupported password prefix '" + prefix + "'");
		}
		// Standard SHA
		return null;
	}

	/**
	 * Returns the hash prefix or null if there isn't one.
	 */
	private String extractPrefix(String encPass) {
		if (!encPass.startsWith("{")) {
			return null;
		}
		int secondBrace = encPass.lastIndexOf('}');
		if (secondBrace < 0) {
			throw new IllegalArgumentException("Couldn't find closing brace for SHA prefix");
		}
		return encPass.substring(0, secondBrace + 1);
	}

	public void setForceLowerCasePrefix(boolean forceLowerCasePrefix) {
		this.forceLowerCasePrefix = forceLowerCasePrefix;
	}

}
