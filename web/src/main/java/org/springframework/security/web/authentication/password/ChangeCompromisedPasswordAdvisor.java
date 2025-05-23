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

import java.util.Collection;

import org.springframework.security.authentication.password.ChangePasswordAdvice;
import org.springframework.security.authentication.password.ChangePasswordAdvice.Action;
import org.springframework.security.authentication.password.ChangePasswordAdvisor;
import org.springframework.security.authentication.password.ChangePasswordReason;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.authentication.password.CompromisedPasswordDecision;
import org.springframework.security.authentication.password.SimpleChangePasswordAdvice;
import org.springframework.security.core.userdetails.UserDetails;

public final class ChangeCompromisedPasswordAdvisor implements ChangePasswordAdvisor {

	private final CompromisedPasswordChecker pwned = new HaveIBeenPwnedRestApiPasswordChecker();

	private Action action = Action.SHOULD_CHANGE;

	@Override
	public ChangePasswordAdvice advise(UserDetails user, String password) {
		return new Advice(this.action, this.pwned.check(password));
	}

	public void setAction(Action action) {
		this.action = action;
	}

	public static final class Advice implements ChangePasswordAdvice {

		private final CompromisedPasswordDecision decision;

		private final ChangePasswordAdvice advice;

		public Advice(Action action, CompromisedPasswordDecision decision) {
			this.decision = decision;
			if (decision.isCompromised()) {
				this.advice = new SimpleChangePasswordAdvice(action, ChangePasswordReason.COMPROMISED);
			}
			else {
				this.advice = ChangePasswordAdvice.keep();
			}
		}

		public CompromisedPasswordDecision getDecision() {
			return this.decision;
		}

		@Override
		public Action getAction() {
			return this.advice.getAction();
		}

		@Override
		public Collection<ChangePasswordReason> getReasons() {
			return this.advice.getReasons();
		}

	}

}
