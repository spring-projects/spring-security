/*
 * Copyright 2021 the original author or authors.
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

import java.util.Arrays;
import java.util.Optional;

/**
 * Hashing algorithms supported by {@link TokenBasedRememberMeServices}
 *
 * @since 5.5
 */
public enum RememberMeHashingAlgorithm {

	UNSET("", ""), MD5("MD5", "MD5"), SHA256("SHA256", "SHA-256");

	private final String identifier;

	private final String digestAlgorithm;

	RememberMeHashingAlgorithm(String identifier, String digestAlgorithm) {
		this.identifier = identifier;
		this.digestAlgorithm = digestAlgorithm;
	}

	/**
	 * The identifier to use in cookies created by {@link TokenBasedRememberMeServices} to
	 * signify this algorithm is being used.
	 *
	 * If empty, then no algorithm will be specified in the resulting cookie.
	 */
	public String getIdentifier() {
		return this.identifier;
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

	static Optional<RememberMeHashingAlgorithm> findByIdentifier(String identifier) {
		return Arrays.stream(values()).filter((algorithm) -> algorithm.getIdentifier().equals(identifier)).findAny();
	}

}
