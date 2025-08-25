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

package org.springframework.security.authentication.password;

import org.jspecify.annotations.NullMarked;

@NullMarked
public class SimplePasswordAdvice implements PasswordAdvice {

	public static final PasswordAdvice NONE = new SimplePasswordAdvice(PasswordAction.NONE);

	private final PasswordAction action;

	public SimplePasswordAdvice(PasswordAction action) {
		this.action = action;
	}

	@Override
	public PasswordAction getAction() {
		return this.action;
	}

	@Override
	public String toString() {
		return "Simple [action=" + this.action + "]";
	}

}
