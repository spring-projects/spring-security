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

public final class PasswordLengthAdvisor implements PasswordAdvisor, UpdatePasswordAdvisor {

	/**
	 * The ASVS v5.0 minimum password length
	 * @see <a href=
	 * "https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv#L108">ASVS
	 * 5.0 Password Security Standard</a>
	 */
	private static final int ASVS_V5_MINIMUM_PASSWORD_LENGTH = 8;

	private final int minLength;

	private final int maxLength;

	private PasswordAction passwordAction = PasswordAction.SHOULD_CHANGE;

	public PasswordLengthAdvisor() {
		this(ASVS_V5_MINIMUM_PASSWORD_LENGTH);
	}

	public PasswordLengthAdvisor(int minLength) {
		this(minLength, Integer.MAX_VALUE);
	}

	public PasswordLengthAdvisor(int minLength, int maxLength) {
		Assert.isTrue(minLength > 0, "minLength must be greater than 0");
		this.minLength = minLength;
		this.maxLength = maxLength;
	}

	@Override
	public PasswordAdvice advise(UserDetails user, @Nullable String password) {
		if (password == null) {
			return new PasswordLengthAdvice(this.passwordAction, this.minLength, this.maxLength, 0);
		}
		if (password.length() < this.minLength) {
			return new PasswordLengthAdvice(this.passwordAction, this.minLength, this.maxLength, password.length());
		}
		if (password.length() > this.maxLength) {
			return new PasswordLengthAdvice(this.passwordAction, this.minLength, this.maxLength, password.length());
		}
		return SimplePasswordAdvice.NONE;
	}

	@Override
	public PasswordAdvice advise(UserDetails user, @Nullable String oldPassword, @Nullable String newPassword) {
		return advise(user, newPassword);
	}

	public void setPasswordAction(PasswordAction passwordAction) {
		this.passwordAction = passwordAction;
	}

	public static final class PasswordLengthAdvice extends SimplePasswordAdvice {

		private final int minLength;

		private final int maxLength;

		private final int actualLength;

		private PasswordLengthAdvice(PasswordAction action, int minLength, int maxLength, int actualLength) {
			super(action);
			this.minLength = minLength;
			this.maxLength = maxLength;
			this.actualLength = actualLength;
		}

		public int getMinLength() {
			return this.minLength;
		}

		public int getMaxLength() {
			return this.maxLength;
		}

		public int getActualLength() {
			return this.actualLength;
		}

		@Override
		public String toString() {
			return "Length [action=" + super.toString() + ", minLength=" + this.minLength + ", maxLength="
					+ this.maxLength + ", actualLength=" + this.actualLength + "]";
		}

	}

}
