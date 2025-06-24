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

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.core.MethodParameter;
import org.springframework.security.authentication.password.ChangePasswordAdvice;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

public final class ChangePasswordAdviceMethodArgumentResolver implements HandlerMethodArgumentResolver {

	ChangePasswordAdviceRepository changePasswordAdviceRepository = new HttpSessionChangePasswordAdviceRepository();

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		return ChangePasswordAdvice.class.isAssignableFrom(parameter.getParameterType());
	}

	@Override
	public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
			NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
		return this.changePasswordAdviceRepository
			.loadPasswordAdvice(webRequest.getNativeRequest(HttpServletRequest.class));
	}

	public void setChangePasswordAdviceRepository(ChangePasswordAdviceRepository changePasswordAdviceRepository) {
		this.changePasswordAdviceRepository = changePasswordAdviceRepository;
	}

}
