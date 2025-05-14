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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.springframework.security.core.userdetails.UserDetails;

public final class DelegatingChangePasswordAdvisor implements ChangePasswordAdvisor {

	private final List<ChangePasswordAdvisor> advisors;

	public DelegatingChangePasswordAdvisor(List<ChangePasswordAdvisor> advisors) {
		this.advisors = advisors;
	}

	@Override
	public ChangePasswordAdvice advise(UserDetails user, String password) {
		Collection<ChangePasswordAdvice> advice = this.advisors.stream()
			.map((advisor) -> advisor.advise(user, password))
			.filter(Objects::nonNull)
			.toList();
		return new CompositeChangePasswordAdvice(advice);
	}

	@Override
	public ChangePasswordAdvice adviseForUpdate(UserDetails user, String password) {
		Collection<ChangePasswordAdvice> advice = this.advisors.stream()
			.map((advisor) -> advisor.adviseForUpdate(user, password))
			.filter(Objects::nonNull)
			.toList();
		return new CompositeChangePasswordAdvice(advice);
	}

	private static final class CompositeChangePasswordAdvice implements ChangePasswordAdvice {

		private final Collection<ChangePasswordAdvice> advice;

		private final Action action;

		private final Collection<ChangePasswordReason> reasons;

		private CompositeChangePasswordAdvice(Collection<ChangePasswordAdvice> advice) {
			this.advice = advice;
			Action action = Action.KEEP;
			Collection<ChangePasswordReason> reasons = new ArrayList<>();
			for (ChangePasswordAdvice a : advice) {
				if (a.getAction() == Action.KEEP) {
					continue;
				}
				if (action.ordinal() < a.getAction().ordinal()) {
					action = a.getAction();
				}
				reasons.addAll(a.getReasons());
			}
			this.action = action;
			this.reasons = reasons;
		}

		@Override
		public Action getAction() {
			return this.action;
		}

		@Override
		public Collection<ChangePasswordReason> getReasons() {
			return this.reasons;
		}

	}

}
