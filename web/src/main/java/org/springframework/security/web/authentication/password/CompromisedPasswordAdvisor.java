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

package org.springframework.security.web.authentication.password;

import org.jspecify.annotations.Nullable;

import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.security.authentication.password.PasswordAction;
import org.springframework.security.authentication.password.PasswordAdvice;
import org.springframework.security.authentication.password.PasswordAdvisor;
import org.springframework.security.authentication.password.UpdatePasswordAdvisor;
import org.springframework.security.core.userdetails.UserDetails;

public final class CompromisedPasswordAdvisor implements PasswordAdvisor, UpdatePasswordAdvisor {

	private final CompromisedPasswordChecker pwned = new HaveIBeenPwnedRestApiPasswordChecker();

	private PasswordAction action = PasswordAction.SHOULD_CHANGE;

	@Override
	public PasswordAdvice advise(UserDetails user, @Nullable String password) {
		if (password == null) {
			return PasswordAdvice.ABSTAIN;
		}
		CompromisedPasswordDecision decision = this.pwned.check(password);
		if (decision.isCompromised()) {
			return new Advice(this.action, decision);
		}
		else {
			return new Advice(PasswordAction.ABSTAIN, decision);
		}
	}

	@Override
	public PasswordAdvice advise(UserDetails user, String oldPassword, String newPassword) {
		return advise(user, newPassword);
	}

	public void setAction(PasswordAction action) {
		this.action = action;
	}

	public static final class Advice implements PasswordAdvice {

		private final PasswordAction action;

		private final CompromisedPasswordDecision decision;

		public Advice(PasswordAction action, CompromisedPasswordDecision decision) {
			this.action = action;
			this.decision = decision;
		}

		public CompromisedPasswordDecision getCompromisedPasswordDecision() {
			return this.decision;
		}

		@Override
		public PasswordAction getAction() {
			return this.action;
		}

		@Override
		public String toString() {
			return "Compromised [" + "action=" + this.action + ", decision=" + this.decision + "]";
		}

	}

}
