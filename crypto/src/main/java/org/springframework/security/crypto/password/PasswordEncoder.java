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

package org.springframework.security.crypto.password;

import org.jspecify.annotations.Nullable;

import org.springframework.lang.Contract;

/**
 * Service interface for encoding passwords.
 *
 * The preferred implementation is {@code BCryptPasswordEncoder}.
 *
 * @author Keith Donald
 * @author Rob Winch
 */
public interface PasswordEncoder {

	/**
	 * Encode the raw password. Generally, a good encoding algorithm uses an adaptive one
	 * way function.
	 * @param rawPassword a password that has not been encoded. The value can be null in
	 * the event that the user has no password; in which case the result must be null.
	 * @return A non-null encoded password, unless the rawPassword was null in which case
	 * the result must be null.
	 */
	@Contract("!null -> !null; null -> null")
	@Nullable String encode(@Nullable CharSequence rawPassword);

	/**
	 * Verify the encoded password obtained from storage matches the submitted raw
	 * password after it too is encoded. Returns true if the passwords match, false if
	 * they do not. The stored password itself is never decoded. Never true if either
	 * rawPassword or encodedPassword is null or an empty String.
	 * @param rawPassword the raw password to encode and match.
	 * @param encodedPassword the encoded password from storage to compare with.
	 * @return true if the raw password, after encoding, matches the encoded password from
	 * storage.
	 */
	boolean matches(@Nullable CharSequence rawPassword, @Nullable String encodedPassword);

	/**
	 * Returns true if the encoded password should be encoded again for better security,
	 * else false. The default implementation always returns false.
	 * @param encodedPassword the encoded password to check. Possibly null if the user did
	 * not have a password.
	 * @return true if the encoded password should be encoded again for better security,
	 * else false. If encodedPassword is null (the user didn't have a password), then
	 * always false.
	 */
	default boolean upgradeEncoding(@Nullable String encodedPassword) {
		return false;
	}

}
