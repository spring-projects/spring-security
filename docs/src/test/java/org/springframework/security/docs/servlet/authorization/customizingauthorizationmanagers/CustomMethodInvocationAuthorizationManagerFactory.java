/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain clients copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.docs.servlet.authorization.customizingauthorizationmanagers;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory;
import org.springframework.stereotype.Component;

/**
 * Documentation for {@link AuthorizationManagerFactory}.
 *
 * @author Steve Riesenberg
 */
// tag::class[]
@Component
public class CustomMethodInvocationAuthorizationManagerFactory
		implements AuthorizationManagerFactory<MethodInvocation> {

	private final AuthorizationManagerFactory<MethodInvocation> delegate =
			new DefaultAuthorizationManagerFactory<>();

	@Override
	public AuthorizationManager<MethodInvocation> hasRole(String role) {
		return AuthorizationManagers.anyOf(
			this.delegate.hasRole(role),
			this.delegate.hasRole("ADMIN")
		);
	}

	@Override
	public AuthorizationManager<MethodInvocation> hasAnyRole(String... roles) {
		return AuthorizationManagers.anyOf(
			this.delegate.hasAnyRole(roles),
			this.delegate.hasRole("ADMIN")
		);
	}

}
// end::class[]
