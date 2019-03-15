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
package org.springframework.security.core.token;

/**
 * Provides a mechanism to allocate and rebuild secure, randomised tokens.
 *
 * <p>
 * Implementations are solely concern with issuing a new {@link Token} on demand. The
 * issued <code>Token</code> may contain user-specified extended information. The token
 * also contains a cryptographically strong, byte array-based key. This permits the token
 * to be used to identify a user session, if desired. The key can subsequently be
 * re-presented to the <code>TokenService</code> for verification and reconstruction of a
 * <code>Token</code> equal to the original <code>Token</code>.
 * </p>
 *
 * <p>
 * Given the tightly-focused behaviour provided by this interface, it can serve as a
 * building block for more sophisticated token-based solutions. For example,
 * authentication systems that depend on stateless session keys. These could, for
 * instance, place the username inside the user-specified extended information associated
 * with the key). It is important to recognise that we do not intend for this interface to
 * be expanded to provide such capabilities directly.
 * </p>
 *
 * @author Ben Alex
 * @since 2.0.1
 *
 */
public interface TokenService {
	/**
	 * Forces the allocation of a new {@link Token}.
	 *
	 * @param extendedInformation the extended information desired in the token (cannot be
	 * <code>null</code>, but can be empty)
	 * @return a new token that has not been issued previously, and is guaranteed to be
	 * recognised by this implementation's {@link #verifyToken(String)} at any future
	 * time.
	 */
	Token allocateToken(String extendedInformation);

	/**
	 * Permits verification the {@link Token#getKey()} was issued by this
	 * <code>TokenService</code> and reconstructs the corresponding <code>Token</code>.
	 *
	 * @param key as obtained from {@link Token#getKey()} and created by this
	 * implementation
	 * @return the token, or <code>null</code> if the token was not issued by this
	 * <code>TokenService</code>
	 */
	Token verifyToken(String key);
}
