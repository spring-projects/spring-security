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

import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.password.PasswordAction;
import org.springframework.security.authentication.password.PasswordAdvice;
import org.springframework.util.function.SingletonSupplier;

public final class HttpSessionPasswordAdviceRepository implements PasswordAdviceRepository {

	private static final String PASSWORD_ADVICE_ATTRIBUTE_NAME = HttpSessionPasswordAdviceRepository.class.getName()
			+ ".PASSWORD_ADVICE";

	@Override
	public PasswordAdvice loadPasswordAdvice(HttpServletRequest request) {
		return new DeferredPasswordAdvice(() -> {
			PasswordAdvice advice = (PasswordAdvice) request.getSession().getAttribute(PASSWORD_ADVICE_ATTRIBUTE_NAME);
			if (advice != null) {
				return advice;
			}
			return PasswordAdvice.ABSTAIN;
		});
	}

	@Override
	public void savePasswordAdvice(HttpServletRequest request, HttpServletResponse response, PasswordAdvice advice) {
		if (advice.getAction() == PasswordAction.ABSTAIN) {
			removePasswordAdvice(request, response);
			return;
		}
		request.getSession().setAttribute(PASSWORD_ADVICE_ATTRIBUTE_NAME, advice);
	}

	@Override
	public void removePasswordAdvice(HttpServletRequest request, HttpServletResponse response) {
		request.getSession().removeAttribute(PASSWORD_ADVICE_ATTRIBUTE_NAME);
	}

	private static final class DeferredPasswordAdvice implements PasswordAdvice {

		private final Supplier<PasswordAdvice> advice;

		DeferredPasswordAdvice(Supplier<PasswordAdvice> advice) {
			this.advice = SingletonSupplier.of(advice);
		}

		@Override
		public PasswordAction getAction() {
			return this.advice.get().getAction();
		}

		PasswordAdvice getChangePasswordAdvice() {
			return this.advice.get();
		}

		@Override
		public String toString() {
			return this.advice.get().toString();
		}

	}

}
