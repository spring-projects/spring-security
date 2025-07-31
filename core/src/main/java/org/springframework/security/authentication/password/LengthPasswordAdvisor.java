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

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

public final class LengthPasswordAdvisor implements PasswordAdvisor, UpdatePasswordAdvisor {

	private final int minLength;

	private final int maxLength;

	private PasswordAction tooShortAction = PasswordAction.MUST_CHANGE;

	private PasswordAction tooLongAction = PasswordAction.SHOULD_CHANGE;

	public LengthPasswordAdvisor() {
		this(12, 64);
	}

	public LengthPasswordAdvisor(int minLength) {
		this(minLength, Integer.MAX_VALUE);
	}

	public LengthPasswordAdvisor(int minLength, int maxLength) {
		Assert.isTrue(minLength > 0, "minLength must be greater than 0");
		this.minLength = minLength;
		this.maxLength = maxLength;
	}

	@Override
	public PasswordAdvice advise(UserDetails user, @Nullable String password) {
		if (password == null) {
			return new TooShortAdvice(this.tooShortAction, this.minLength, 0);
		}
		if (password.length() < this.minLength) {
			return new TooShortAdvice(this.tooShortAction, this.minLength, password.length());
		}
		if (password.length() > this.maxLength) {
			return new TooLongAdvice(this.tooLongAction, this.maxLength, password.length());
		}
		return PasswordAdvice.ABSTAIN;
	}

	@Override
	public PasswordAdvice advise(UserDetails user, @Nullable String oldPassword, @Nullable String newPassword) {
		return advise(user, newPassword);
	}

	public void setTooShortAction(PasswordAction tooShortAction) {
		this.tooShortAction = tooShortAction;
	}

	public void setTooLongAction(PasswordAction tooLongAction) {
		this.tooLongAction = tooLongAction;
	}

	public static final class TooShortAdvice implements PasswordAdvice {

		private final PasswordAction action;

		private final int minLength;

		private final int actualLength;

		private TooShortAdvice(PasswordAction action, int minLength, int actualLength) {
			this.action = action;
			this.minLength = minLength;
			this.actualLength = actualLength;
		}

		@Override
		public PasswordAction getAction() {
			return this.action;
		}

		public int getMinLength() {
			return this.minLength;
		}

		public int getActualLength() {
			return this.actualLength;
		}

		@Override
		public String toString() {
			return "TooShort [" + "action=" + this.action + ", minLength=" + this.minLength + ", actualLength="
					+ this.actualLength + "]";
		}

	}

	public static final class TooLongAdvice implements PasswordAdvice {

		private final PasswordAction action;

		private final int maxLength;

		private final int actualLength;

		private TooLongAdvice(PasswordAction action, int maxLength, int actualLength) {
			this.action = action;
			this.maxLength = maxLength;
			this.actualLength = actualLength;
		}

		@Override
		public PasswordAction getAction() {
			return this.action;
		}

		public int getMaxLength() {
			return this.maxLength;
		}

		public int getActualLength() {
			return this.actualLength;
		}

		@Override
		public String toString() {
			return "TooLong [" + "action=" + this.action + ", maxLength=" + this.maxLength + ", actualLength="
					+ this.actualLength + "]";
		}

	}

}
