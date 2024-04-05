/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.annotation.method.configuration;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.method.AuthorizationDeniedHandler;
import org.springframework.security.authorization.method.MethodAuthorizationDeniedPostProcessor;
import org.springframework.security.authorization.method.MethodInvocationResult;

public class UserRecordWithEmailProtected {

	private final String name;

	private final String email;

	public UserRecordWithEmailProtected(String name, String email) {
		this.name = name;
		this.email = email;
	}

	public String name() {
		return this.name;
	}

	@PostAuthorize("hasRole('ADMIN')")
	@AuthorizationDeniedHandler(postProcessorClass = EmailMaskingPostProcessor.class)
	public String email() {
		return this.email;
	}

	public static class EmailMaskingPostProcessor implements MethodAuthorizationDeniedPostProcessor {

		@Override
		public Object postProcessResult(MethodInvocationResult methodInvocationResult,
				AuthorizationResult authorizationResult) {
			String email = (String) methodInvocationResult.getResult();
			return email.replaceAll("(^[^@]{3}|(?!^)\\G)[^@]", "$1*");
		}

	}

}
