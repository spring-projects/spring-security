/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.method;

import java.util.Map;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.Pointcut;
import org.springframework.aop.support.AopUtils;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;

class PointcutDelegatingAuthorizationManager implements AuthorizationManager<MethodInvocation> {

	private final Map<Pointcut, AuthorizationManager<MethodInvocation>> managers;

	PointcutDelegatingAuthorizationManager(Map<Pointcut, AuthorizationManager<MethodInvocation>> managers) {
		this.managers = managers;
	}

	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocation object) {
		for (Map.Entry<Pointcut, AuthorizationManager<MethodInvocation>> entry : this.managers.entrySet()) {
			Class<?> targetClass = (object.getThis() != null) ? AopUtils.getTargetClass(object.getThis()) : null;
			if (entry.getKey().getClassFilter().matches(targetClass)
					&& entry.getKey().getMethodMatcher().matches(object.getMethod(), targetClass)) {
				return entry.getValue().check(authentication, object);
			}
		}
		return new AuthorizationDecision(false);
	}

}
