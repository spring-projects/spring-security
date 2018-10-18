/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.crypto.bcrypt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.SecureRandom;
import java.util.regex.Pattern;

/**
 * Implementation of PasswordEncoder that uses the BCrypt strong hashing function. Clients
 * can optionally supply a "strength" (a.k.a. log rounds in BCrypt) and a SecureRandom
 * instance. The larger the strength parameter the more work will have to be done
 * (exponentially) to hash the passwords. The default value is 10.
 *
 * @author Dave Syer
 *
 */
public class BCryptPasswordEncoder implements PasswordEncoder {
	private Pattern BCRYPT_PATTERN = Pattern
			.compile("\\A\\$2(a|y|b)?\\$\\d\\d\\$[./0-9A-Za-z]{53}");
	private final Log logger = LogFactory.getLog(getClass());

	private final int strength;
	private final String version;

	private final SecureRandom random;


	public BCryptPasswordEncoder() {
		this(-1);
	}

	/**
	 * @param strength the log rounds to use, between 4 and 31
	 */
	public BCryptPasswordEncoder(int strength) {
		this(strength, null);
	}

	/**
	 * @param version the version of bcrypt, can be 2a,2b,2y
	 */
	public BCryptPasswordEncoder(String version) {
		this(version, null);
	}

	/**
	 * @param version the version of bcrypt, can be 2a,2b,2y
	 * @param random the secure random instance to use
	 */
	public BCryptPasswordEncoder(String version, SecureRandom random) {
		this(version, -1, random);
	}

	/**
	 * @param strength the log rounds to use, between 4 and 31
	 * @param random the secure random instance to use
	 *
	 */
	public BCryptPasswordEncoder(int strength, SecureRandom random) {
		this(null, strength, random);
	}

	/**
	 * @param version the version of bcrypt, can be 2a,2b,2y
	 * @param strength the log rounds to use, between 4 and 31
	 */
	public BCryptPasswordEncoder(String version, int strength) {
		this(version, strength, null);
	}

	/**
	 * @param version the version of bcrypt, can be 2a,2b,2y
	 * @param strength the log rounds to use, between 4 and 31
	 * @param random the secure random instance to use
	 *
	 */
	public BCryptPasswordEncoder(String version, int strength, SecureRandom random) {
		if (strength != -1 && (strength < BCrypt.MIN_LOG_ROUNDS || strength > BCrypt.MAX_LOG_ROUNDS)) {
			throw new IllegalArgumentException("Bad strength");
		}
		this.version = version;
		this.strength = strength;
		this.random = random;
	}

	public String encode(CharSequence rawPassword) {
		String salt;
		if(version != null) {
			if (strength > 0) {
				if (random != null) {
					salt = BCrypt.gensalt(version, strength, random);
				} else {
					System.out.println(version);
					salt = BCrypt.gensalt(version, strength);
				}
			} else {
				salt = BCrypt.gensalt(version);
			}
		} else {
			if (strength > 0) {
				if (random != null) {
					salt = BCrypt.gensalt(strength, random);
				} else {
					salt = BCrypt.gensalt(strength);
				}
			} else {
				salt = BCrypt.gensalt();
			}
		}
		return BCrypt.hashpw(rawPassword.toString(), salt);
	}

	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		if (encodedPassword == null || encodedPassword.length() == 0) {
			logger.warn("Empty encoded password");
			return false;
		}

		if (!BCRYPT_PATTERN.matcher(encodedPassword).matches()) {
			logger.warn("Encoded password does not look like BCrypt");
			return false;
		}

		return BCrypt.checkpw(rawPassword.toString(), encodedPassword);
	}

	public static final String BCRYPT_VERSION_2A = "$2a";
	public static final String BCRYPT_VERSION_2Y = "$2y";
	public static final String BCRYPT_VERSION_2B = "$2b";
}
