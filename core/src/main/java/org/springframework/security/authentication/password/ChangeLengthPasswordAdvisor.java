/*
 * Copyright 2025 the original author or authors.
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

import org.springframework.security.authentication.password.ChangePasswordAdvice.Action;
import org.springframework.security.core.userdetails.UserDetails;

public class ChangeLengthPasswordAdvisor implements ChangePasswordAdvisor {

	private final int minLength;

	private final int maxLength;

	private Action tooShortAction = Action.MUST_CHANGE;

	private Action tooLongAction = Action.SHOULD_CHANGE;

	public ChangeLengthPasswordAdvisor(int minLength) {
		this(minLength, Integer.MAX_VALUE);
	}

	public ChangeLengthPasswordAdvisor(int minLength, int maxLength) {
		this.minLength = minLength;
		this.maxLength = maxLength;
	}

	@Override
	public ChangePasswordAdvice advise(UserDetails user, String password) {
		if (password.length() < this.minLength) {
			return new SimpleChangePasswordAdvice(this.tooShortAction, ChangePasswordReasons.TOO_SHORT);
		}
		if (password.length() > this.maxLength) {
			return new SimpleChangePasswordAdvice(this.tooLongAction, ChangePasswordReasons.TOO_LONG);
		}
		return ChangePasswordAdvice.abstain();
	}

	public void setTooShortAction(Action tooShortAction) {
		this.tooShortAction = tooShortAction;
	}

	public void setTooLongAction(Action tooLongAction) {
		this.tooLongAction = tooLongAction;
	}

}
