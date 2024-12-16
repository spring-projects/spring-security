/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.messaging.util.matcher;

import org.springframework.messaging.Message;

/**
 * API for determining if a {@link Message} should be matched on.
 *
 * @author Rob Winch
 * @since 4.0
 */
public interface MessageMatcher<T> {

	/**
	 * Matches every {@link Message}
	 */
	MessageMatcher<Object> ANY_MESSAGE = new MessageMatcher<>() {

		@Override
		public boolean matches(Message<?> message) {
			return true;
		}

		@Override
		public String toString() {
			return "ANY_MESSAGE";
		}

	};

	/**
	 * Returns true if the {@link Message} matches, else false
	 * @param message the {@link Message} to match on
	 * @return true if the {@link Message} matches, else false
	 */
	boolean matches(Message<? extends T> message);

}
