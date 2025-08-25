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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.userdetails.UserDetails;

public final class CompositePasswordAdvisor implements PasswordAdvisor {

	private final Collection<PasswordAdvisor> advisors;

	private CompositePasswordAdvisor(Collection<PasswordAdvisor> advisors) {
		this.advisors = Collections.unmodifiableCollection(advisors);
	}

	public static PasswordAdvisor of(PasswordAdvisor... advisors) {
		return new CompositePasswordAdvisor(List.of(advisors));
	}

	public static PasswordAdvisor withDefaults(PasswordAdvisor... advisors) {
		Map<Class<? extends PasswordAdvisor>, PasswordAdvisor> defaults = new HashMap<>();
		defaults.put(UserDetailsPasswordAdvisor.class, new UserDetailsPasswordAdvisor());
		defaults.put(PasswordLengthAdvisor.class, new PasswordLengthAdvisor());
		for (PasswordAdvisor advisor : advisors) {
			defaults.put(advisor.getClass(), advisor);
		}
		return new CompositePasswordAdvisor(defaults.values());
	}

	@Override
	public PasswordAdvice advise(UserDetails user, @Nullable String password) {
		Collection<PasswordAdvice> advice = this.advisors.stream()
			.map((advisor) -> advisor.advise(user, password))
			.toList();
		return new CompositePasswordAdvice(advice);
	}

	public static final class CompositePasswordAdvice extends SimplePasswordAdvice {

		private final Collection<PasswordAdvice> advice;

		private CompositePasswordAdvice(Collection<PasswordAdvice> advice) {
			super(findMostUrgentAction(advice));
			this.advice = advice;
		}

		private static PasswordAction findMostUrgentAction(Collection<PasswordAdvice> advice) {
			PasswordAction mostUrgentAction = PasswordAction.NONE;
			for (PasswordAdvice a : advice) {
				if (mostUrgentAction.ordinal() < a.getAction().ordinal()) {
					mostUrgentAction = a.getAction();
				}
			}
			return mostUrgentAction;
		}

		public Collection<PasswordAdvice> getAdvice() {
			return this.advice;
		}

		@Override
		public String toString() {
			return "Composite [" + "action=" + super.toString() + ", advice=" + this.advice + "]";
		}

	}

}
