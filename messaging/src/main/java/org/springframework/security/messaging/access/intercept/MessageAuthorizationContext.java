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

package org.springframework.security.messaging.access.intercept;

import java.util.Collections;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.messaging.Message;

/**
 * An {@link Message} authorization context.
 *
 * @author Josh Cummings
 * @since 5.8
 */
public final class MessageAuthorizationContext<T> {

	private final Message<T> message;

	private final Map<String, String> variables;

	/**
	 * Creates an instance.
	 * @param message the {@link HttpServletRequest} to use
	 */
	public MessageAuthorizationContext(Message<T> message) {
		this(message, Collections.emptyMap());
	}

	/**
	 * Creates an instance.
	 * @param message the {@link HttpServletRequest} to use
	 * @param variables a map containing key-value pairs representing extracted variable
	 * names and variable values
	 */
	public MessageAuthorizationContext(Message<T> message, Map<String, String> variables) {
		this.message = message;
		this.variables = variables;
	}

	/**
	 * Returns the {@link HttpServletRequest}.
	 * @return the {@link HttpServletRequest} to use
	 */
	public Message<T> getMessage() {
		return this.message;
	}

	/**
	 * Returns the extracted variable values where the key is the variable name and the
	 * value is the variable value.
	 * @return a map containing key-value pairs representing extracted variable names and
	 * variable values
	 */
	public Map<String, String> getVariables() {
		return this.variables;
	}

}
