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

package org.springframework.security.authentication.apikey;

/**
 * Handles API key hashing and encoding into string as well as securely comparing hashes.
 *
 * @author Alexey Razinkov
 * @see org.springframework.security.crypto.password.PasswordEncoder
 */
public interface ApiKeyDigest {

	/**
	 * Hashes API key secret and encodes resulting byte array to string.
	 * @param apiKeySecret API key secret bytes
	 * @return Hash encoded into string
	 */
	String digest(byte[] apiKeySecret);

	/**
	 * Hashes provided API key secret and compares it against provided hash.
	 * @param apiKeySecret API key secret to hash
	 * @param digest Existing API key secret hash
	 * @return True if hash of provided API key secret matches existing hash
	 */
	boolean matches(byte[] apiKeySecret, String digest);

	/**
	 * @return Hash created of some dummy value for mitigating timing attack
	 */
	String getDummyDigest();

}
