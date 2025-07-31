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

package org.springframework.security.web.authentication.password;

import org.springframework.security.authentication.password.ChangePasswordAdvice;
import org.springframework.security.authentication.password.ChangePasswordAdvice.Action;
import org.springframework.security.authentication.password.ChangePasswordAdvisor;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.security.core.userdetails.UserDetails;

public final class ChangeCompromisedPasswordAdvisor implements ChangePasswordAdvisor {

	private final CompromisedPasswordChecker pwned = new HaveIBeenPwnedRestApiPasswordChecker();

	private Action action = Action.SHOULD_CHANGE;

	@Override
	public ChangePasswordAdvice advise(UserDetails user, String password) {
		CompromisedPasswordDecision decision = this.pwned.check(password);
		if (decision.isCompromised()) {
			return new Advice(this.action, decision);
		} else {
			return new Advice(Action.ABSTAIN, decision);
		}
	}

	public void setAction(Action action) {
		this.action = action;
	}

	public static final class Advice implements ChangePasswordAdvice {

		private final Action action;

		private final CompromisedPasswordDecision decision;

		public Advice(Action action, CompromisedPasswordDecision decision) {
			this.action = action;
			this.decision = decision;
		}

		public CompromisedPasswordDecision getCompromisedPasswordDecision() {
			return this.decision;
		}

		@Override
		public Action getAction() {
			return this.action;
		}

		@Override
		public String toString() {
			return "Compromised [" +
					"action=" + this.action +
					", decision=" + this.decision +
					"]";
		}
	}

}
