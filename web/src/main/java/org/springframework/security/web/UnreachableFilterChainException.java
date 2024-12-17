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

package org.springframework.security.web;

import org.springframework.security.core.SpringSecurityCoreVersion;

/**
 * Thrown if {@link SecurityFilterChain securityFilterChain} is not valid.
 *
 * @author Max Batischev
 * @since 6.5
 */
public class UnreachableFilterChainException extends IllegalArgumentException {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final SecurityFilterChain filterChain;

	private final SecurityFilterChain unreachableFilterChain;

	/**
	 * Constructs an <code>UnreachableFilterChainException</code> with the specified
	 * message.
	 * @param message the detail message
	 */
	public UnreachableFilterChainException(String message, SecurityFilterChain filterChain,
			SecurityFilterChain unreachableFilterChain) {
		super(message);
		this.filterChain = filterChain;
		this.unreachableFilterChain = unreachableFilterChain;
	}

	public SecurityFilterChain getFilterChain() {
		return this.filterChain;
	}

	public SecurityFilterChain getUnreachableFilterChain() {
		return this.unreachableFilterChain;
	}

}
