/*
 * Copyright 2015-2024 the original author or authors.
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

package org.springframework.security.web.authentication.session;

import java.util.function.Function;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * Represents the maximum number of sessions allowed. Use {@link #UNLIMITED} to indicate
 * that there is no limit.
 *
 * @author Claudenir Freitas
 * @since 6.5
 */
public interface SessionLimit extends Function<Authentication, Integer> {

	/**
	 * Represents unlimited sessions.
	 */
	SessionLimit UNLIMITED = (authentication) -> -1;

	/**
	 * Creates a {@link SessionLimit} that always returns the given value for any user
	 * @param maxSessions the maximum number of sessions allowed
	 * @return a {@link SessionLimit} instance that returns the given value.
	 */
	static SessionLimit of(int maxSessions) {
		Assert.isTrue(maxSessions != 0,
				"MaximumLogins must be either -1 to allow unlimited logins, or a positive integer to specify a maximum");
		return (authentication) -> maxSessions;
	}

}
