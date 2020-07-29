/*
 * Copyright 2011-2016 the original author or authors.
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

/**
 * This {@link PasswordEncoder} is provided for legacy and testing purposes only and is
 * not considered secure.
 *
 * A password encoder that does nothing. Useful for testing where working with plain text
 * passwords may be preferred.
 *
 * @author Keith Donald
 * @deprecated This PasswordEncoder is not secure. Instead use an adaptive one way
 * function like BCryptPasswordEncoder, Pbkdf2PasswordEncoder, or SCryptPasswordEncoder.
 * Even better use {@link DelegatingPasswordEncoder} which supports password upgrades.
 * There are no plans to remove this support. It is deprecated to indicate that this is a
 * legacy implementation and using it is considered insecure.
 */
@Deprecated
public final class NoOpPasswordEncoder implements PasswordEncoder {

	@Override
	public String encode(CharSequence rawPassword) {
		return rawPassword.toString();
	}

	@Override
	public boolean matches(CharSequence rawPassword, String encodedPassword) {
		return rawPassword.toString().equals(encodedPassword);
	}

	/**
	 * Get the singleton {@link NoOpPasswordEncoder}.
	 */
	public static PasswordEncoder getInstance() {
		return INSTANCE;
	}

	private static final PasswordEncoder INSTANCE = new NoOpPasswordEncoder();

	private NoOpPasswordEncoder() {
	}

}
