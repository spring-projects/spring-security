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
import java.util.Collections;
import java.util.List;

import org.springframework.security.core.userdetails.UserDetails;

public final class DelegatingChangePasswordAdvisor implements ChangePasswordAdvisor {

	private final List<ChangePasswordAdvisor> advisors;

	private DelegatingChangePasswordAdvisor(List<ChangePasswordAdvisor> advisors) {
		this.advisors = Collections.unmodifiableList(advisors);
	}

	public static ChangePasswordAdvisor of(ChangePasswordAdvisor... advisors) {
		return new DelegatingChangePasswordAdvisor(List.of(advisors));
	}

	@Override
	public ChangePasswordAdvice advise(UserDetails user, String password) {
		Collection<ChangePasswordAdvice> advice = this.advisors.stream()
			.map((advisor) -> advisor.advise(user, password))
			.filter((a) -> a.getAction() != ChangePasswordAdvice.Action.ABSTAIN)
			.toList();
		return new CompositeChangePasswordAdvice(advice);
	}

	private static final class CompositeChangePasswordAdvice implements ChangePasswordAdvice {

		private final Action action;

		private final Collection<String> reasons;

		private CompositeChangePasswordAdvice(Collection<ChangePasswordAdvice> advice) {
			Action mostUrgentAction = Action.ABSTAIN;
			Collection<String> reasons = new ArrayList<>();
			for (ChangePasswordAdvice a : advice) {
				if (mostUrgentAction.ordinal() < a.getAction().ordinal()) {
					mostUrgentAction = a.getAction();
				}
				reasons.addAll(a.getReasons());
			}
			this.action = mostUrgentAction;
			this.reasons = reasons;
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

}
