/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.web.authentication.rememberme;

/**
 * Hashing algorithms supported by {@link TokenBasedRememberMeServices}
 *
 * @since 5.7
 */
public enum RememberMeHashingAlgorithm {

	MD5("MD5"), SHA256("SHA-256");

	private final String digestAlgorithm;

	RememberMeHashingAlgorithm(String digestAlgorithm) {
		this.digestAlgorithm = digestAlgorithm;
	}

	/**
	 * The name of the algorithm to use
	 *
	 * The output should be acceptable for being passed to
	 * {@link java.security.MessageDigest#getInstance(String)}.
	 */
	public String getDigestAlgorithm() {
		return this.digestAlgorithm;
	}

	public static RememberMeHashingAlgorithm from(String name) {
		for (RememberMeHashingAlgorithm algorithm : values()) {
			if (algorithm.name().equals(name)) {
				return algorithm;
			}
		}
		return null;
	}

}
