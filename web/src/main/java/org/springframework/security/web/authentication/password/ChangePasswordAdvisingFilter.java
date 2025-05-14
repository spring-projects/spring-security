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

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.password.ChangePasswordAdvice;
import org.springframework.web.filter.OncePerRequestFilter;

public class ChangePasswordAdvisingFilter extends OncePerRequestFilter {

	private ChangePasswordAdviceHandler changePasswordAdviceHandler = new SimpleChangePasswordAdviceHandler(
			DefaultChangePasswordPageGeneratingFilter.DEFAULT_CHANGE_PASSWORD_URL);

	private ChangePasswordAdviceRepository changePasswordAdviceRepository = new HttpSessionChangePasswordAdviceRepository();

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		ChangePasswordAdvice advice = this.changePasswordAdviceRepository.loadPasswordAdvice(request);
		this.changePasswordAdviceHandler.handle(request, response, chain, advice);
	}

	public void setChangePasswordAdviceRepository(ChangePasswordAdviceRepository changePasswordAdviceRepository) {
		this.changePasswordAdviceRepository = changePasswordAdviceRepository;
	}

	public void setChangePasswordAdviceHandler(ChangePasswordAdviceHandler changePasswordAdviceHandler) {
		this.changePasswordAdviceHandler = changePasswordAdviceHandler;
	}

}
