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

import java.util.Collection;
import java.util.Collections;
import java.util.List;

import org.springframework.security.core.userdetails.UserDetails;

public final class CompositeChangePasswordAdvisor implements ChangePasswordAdvisor {

	private final List<ChangePasswordAdvisor> advisors;

	private CompositeChangePasswordAdvisor(List<ChangePasswordAdvisor> advisors) {
		this.advisors = Collections.unmodifiableList(advisors);
	}

	public static ChangePasswordAdvisor of(ChangePasswordAdvisor... advisors) {
		return new CompositeChangePasswordAdvisor(List.of(advisors));
	}

	@Override
	public ChangePasswordAdvice advise(UserDetails user, String password) {
		Collection<ChangePasswordAdvice> advice = this.advisors.stream()
			.map((advisor) -> advisor.advise(user, password))
			.toList();
		return new Advice(advice);
	}

	public static final class Advice implements ChangePasswordAdvice {

		private final Action action;

		private final Collection<ChangePasswordAdvice> advice;

		private Advice(Collection<ChangePasswordAdvice> advice) {
			this.action = findMostUrgentAction(advice);
			this.advice = advice;
		}

		private Action findMostUrgentAction(Collection<ChangePasswordAdvice> advice) {
			Action mostUrgentAction = Action.ABSTAIN;
			for (ChangePasswordAdvice a : advice) {
				if (mostUrgentAction.ordinal() < a.getAction().ordinal()) {
					mostUrgentAction = a.getAction();
				}
			}
			return mostUrgentAction;
		}

		@Override
		public Action getAction() {
			return this.action;
		}

		public Collection<ChangePasswordAdvice> getAdvice() {
			return this.advice;
		}

		@Override
		public String toString() {
			return "Composite [" +
					"action=" + this.action +
					", advice=" + this.advice +
					"]";
		}
	}

}
