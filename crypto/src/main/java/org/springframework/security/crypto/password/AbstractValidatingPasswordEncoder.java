/*
 * Copyright 2002-2025 the original author or authors.
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

public abstract class AbstractValidatingPasswordEncoder implements PasswordEncoder {

	@Override
	public final @Nullable String encode(@Nullable CharSequence rawPassword) {
		if (rawPassword == null) {
			return null;
		}
		return encodeNonNullPassword(rawPassword.toString());
	}

	protected abstract String encodeNonNullPassword(String rawPassword);

	@Override
	public final boolean matches(@Nullable CharSequence rawPassword, @Nullable String encodedPassword) {
		if (rawPassword == null || rawPassword.length() == 0 || encodedPassword == null
				|| encodedPassword.length() == 0) {
			return false;
		}
		return matchesNonNull(rawPassword.toString(), encodedPassword);
	}

	protected abstract boolean matchesNonNull(String rawPassword, String encodedPassword);

	@Override
	public final boolean upgradeEncoding(@Nullable String encodedPassword) {
		if (encodedPassword == null || encodedPassword.length() == 0) {
			return false;
		}
		return upgradeEncodingNonNull(encodedPassword);
	}

	protected boolean upgradeEncodingNonNull(String encodedPassword) {
		return false;
	}

}
