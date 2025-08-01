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

package org.springframework.security.authorization;

import java.io.Serial;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class AuthorizationDecision implements AuthorizationResult {

	@Serial
	private static final long serialVersionUID = -3226018324649244416L;

	private final boolean granted;

	public AuthorizationDecision(boolean granted) {
		this.granted = granted;
	}

	@Override
	public boolean isGranted() {
		return this.granted;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " [granted=" + this.granted + "]";
	}

}
