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

import org.springframework.util.StringUtils;

/**
 * Implementation of PasswordEncoder.
 *
 * @author Rob Winch
 * @since 7.0
 */
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
		if (StringUtils.hasLength(rawPassword) && StringUtils.hasLength(encodedPassword)) {
			return matchesNonNull(rawPassword.toString(), encodedPassword);
		}
		return false;
	}

	protected abstract boolean matchesNonNull(String rawPassword, String encodedPassword);

	@Override
	public final boolean upgradeEncoding(@Nullable String encodedPassword) {
		if (StringUtils.hasLength(encodedPassword)) {
			return upgradeEncodingNonNull(encodedPassword);
		}
		return false;
	}

	protected boolean upgradeEncodingNonNull(String encodedPassword) {
		return false;
	}

}
