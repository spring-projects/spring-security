/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.authorization.method;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import reactor.core.publisher.Mono;

import org.springframework.aop.Pointcut;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * A {@link MethodInterceptor} which can determine if an {@link Authentication} has access
 * to the returned object from the {@link MethodInvocation} using the configured
 * {@link ReactiveAuthorizationManager}.
 *
 * @author Evgeniy Cheban
 */
public final class ReactiveAuthorizationManagerAfterMethodInterceptor extends AbstractReactiveMethodInterceptor {

	private final ReactiveAuthorizationManager<MethodInvocationResult> authorizationManager;

	/**
	 * Creates an instance for the {@link PostAuthorize} annotation.
	 * @return the {@link ReactiveAuthorizationManagerAfterMethodInterceptor} to use
	 */
	public static ReactiveAuthorizationManagerAfterMethodInterceptor postAuthorize() {
		return postAuthorize(new PostAuthorizeReactiveAuthorizationManager());
	}

	/**
	 * Creates an instance for the {@link PostAuthorize} annotation.
	 * @param authorizationManager the {@link ReactiveAuthorizationManager} to use
	 * @return the {@link ReactiveAuthorizationManagerAfterMethodInterceptor} to use
	 */
	public static ReactiveAuthorizationManagerAfterMethodInterceptor postAuthorize(
			ReactiveAuthorizationManager<MethodInvocationResult> authorizationManager) {
		ReactiveAuthorizationManagerAfterMethodInterceptor interceptor = new ReactiveAuthorizationManagerAfterMethodInterceptor(
				AuthorizationMethodPointcuts.forAnnotations(PostAuthorize.class), authorizationManager);
		interceptor.setOrder(AuthorizationInterceptorsOrder.POST_AUTHORIZE.getOrder());
		return interceptor;
	}

	/**
	 * Creates an instance.
	 * @param pointcut the {@link Pointcut} to use
	 * @param authorizationManager the {@link ReactiveAuthorizationManager} to use
	 */
	public ReactiveAuthorizationManagerAfterMethodInterceptor(Pointcut pointcut,
			ReactiveAuthorizationManager<MethodInvocationResult> authorizationManager) {
		super(pointcut);
		Assert.notNull(authorizationManager, "authorizationManager cannot be null");
		this.authorizationManager = authorizationManager;
	}

	/**
	 * Determines if an {@link Authentication} has access to the returned object from the
	 * {@link MethodInvocation} using the configured {@link ReactiveAuthorizationManager}.
	 * @param authentication the {@link Mono} of the {@link Authentication} to check
	 * @param result the {@link MethodInvocationResult} to check
	 * @return the {@link Mono} of the {@link MethodInvocationResult#getResult()} if
	 * access is granted or a {@link Mono} error if access is denied
	 */
	@Override
	protected Mono<?> after(Mono<Authentication> authentication, MethodInvocationResult result) {
		// @formatter:off
		return this.authorizationManager.verify(authentication, result)
				.thenReturn(result.getResult());
		// @formatter:on
	}

}
