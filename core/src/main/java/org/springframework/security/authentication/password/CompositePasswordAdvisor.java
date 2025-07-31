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

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.userdetails.UserDetails;

public final class CompositePasswordAdvisor implements PasswordAdvisor {

	private final List<PasswordAdvisor> advisors;

	private CompositePasswordAdvisor(List<PasswordAdvisor> advisors) {
		this.advisors = Collections.unmodifiableList(advisors);
	}

	public static PasswordAdvisor of(PasswordAdvisor... advisors) {
		return new CompositePasswordAdvisor(List.of(advisors));
	}

	@Override
	public PasswordAdvice advise(UserDetails user, @Nullable String password) {
		Collection<PasswordAdvice> advice = this.advisors.stream()
			.map((advisor) -> advisor.advise(user, password))
			.toList();
		return new Advice(advice);
	}

	public static final class Advice implements PasswordAdvice {

		private final PasswordAction action;

		private final Collection<PasswordAdvice> advice;

		private Advice(Collection<PasswordAdvice> advice) {
			this.action = findMostUrgentAction(advice);
			this.advice = advice;
		}

		private PasswordAction findMostUrgentAction(Collection<PasswordAdvice> advice) {
			PasswordAction mostUrgentAction = PasswordAction.ABSTAIN;
			for (PasswordAdvice a : advice) {
				if (mostUrgentAction.ordinal() < a.getAction().ordinal()) {
					mostUrgentAction = a.getAction();
				}
			}
			return mostUrgentAction;
		}

		@Override
		public PasswordAction getAction() {
			return this.action;
		}

		public Collection<PasswordAdvice> getAdvice() {
			return this.advice;
		}

		@Override
		public String toString() {
			return "Composite [" + "action=" + this.action + ", advice=" + this.advice + "]";
		}

	}

}
