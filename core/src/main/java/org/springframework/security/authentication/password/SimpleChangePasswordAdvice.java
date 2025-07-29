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

package org.springframework.security.authentication.password;

import java.util.Collection;
import java.util.List;

public class SimpleChangePasswordAdvice implements ChangePasswordAdvice {

	static final SimpleChangePasswordAdvice ABSTAIN = new SimpleChangePasswordAdvice(Action.ABSTAIN);

	private final Action action;

	private final Collection<String> reasons;

	public SimpleChangePasswordAdvice(Action action, Collection<String> reasons) {
		this.action = action;
		this.reasons = reasons;
	}

	public SimpleChangePasswordAdvice(Action action, String... reasons) {
		this.action = action;
		this.reasons = List.of(reasons);
	}

	@Override
	public Action getAction() {
		return this.action;
	}

	@Override
	public Collection<String> getReasons() {
		return this.reasons;
	}

}
