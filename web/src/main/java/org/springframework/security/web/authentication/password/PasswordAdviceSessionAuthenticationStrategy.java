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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.password.PasswordAdvice;
import org.springframework.security.authentication.password.PasswordAdvisor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.util.Assert;

public final class PasswordAdviceSessionAuthenticationStrategy implements SessionAuthenticationStrategy {

	private PasswordAdviceRepository passwordAdviceRepository = new HttpSessionPasswordAdviceRepository();

	private PasswordAdvisor passwordAdvisor = new CompromisedPasswordAdvisor();

	private final String passwordParameter;

	public PasswordAdviceSessionAuthenticationStrategy(String passwordParameter) {
		this.passwordParameter = passwordParameter;
	}

	@Override
	public void onAuthentication(Authentication authentication, HttpServletRequest request,
			HttpServletResponse response) throws SessionAuthenticationException {
		UserDetails user = (UserDetails) authentication.getPrincipal();
		Assert.notNull(user, "cannot persist password advice since user principal is null");
		String password = request.getParameter(this.passwordParameter);
		PasswordAdvice advice = this.passwordAdvisor.advise(user, password);
		this.passwordAdviceRepository.savePasswordAdvice(request, response, advice);
	}

	public void setPasswordAdviceRepository(PasswordAdviceRepository passwordAdviceRepository) {
		this.passwordAdviceRepository = passwordAdviceRepository;
	}

	public void setPasswordAdvisor(PasswordAdvisor passwordAdvisor) {
		this.passwordAdvisor = passwordAdvisor;
	}

}
