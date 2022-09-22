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

package org.springframework.security.config.annotation.method.configuration;

import io.micrometer.observation.ObservationRegistry;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.ObservationReactiveAuthorizationManager;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerAfterReactiveMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeReactiveMethodInterceptor;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.authorization.method.PostAuthorizeReactiveAuthorizationManager;
import org.springframework.security.authorization.method.PostFilterAuthorizationReactiveMethodInterceptor;
import org.springframework.security.authorization.method.PreAuthorizeReactiveAuthorizationManager;
import org.springframework.security.authorization.method.PreFilterAuthorizationReactiveMethodInterceptor;
import org.springframework.security.config.core.GrantedAuthorityDefaults;

/**
 * Configuration for a {@link ReactiveAuthenticationManager} based Method Security.
 *
 * @author Evgeniy Cheban
 * @since 5.8
 */
@Configuration(proxyBeanMethods = false)
final class ReactiveAuthorizationManagerMethodSecurityConfiguration {

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static PreFilterAuthorizationReactiveMethodInterceptor preFilterInterceptor(
			MethodSecurityExpressionHandler expressionHandler) {
		return new PreFilterAuthorizationReactiveMethodInterceptor(expressionHandler);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static AuthorizationManagerBeforeReactiveMethodInterceptor preAuthorizeInterceptor(
			MethodSecurityExpressionHandler expressionHandler, ObjectProvider<ObservationRegistry> registryProvider) {
		ReactiveAuthorizationManager<MethodInvocation> authorizationManager = manager(
				new PreAuthorizeReactiveAuthorizationManager(expressionHandler), registryProvider);
		return AuthorizationManagerBeforeReactiveMethodInterceptor.preAuthorize(authorizationManager);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static PostFilterAuthorizationReactiveMethodInterceptor postFilterInterceptor(
			MethodSecurityExpressionHandler expressionHandler) {
		return new PostFilterAuthorizationReactiveMethodInterceptor(expressionHandler);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static AuthorizationManagerAfterReactiveMethodInterceptor postAuthorizeInterceptor(
			MethodSecurityExpressionHandler expressionHandler, ObjectProvider<ObservationRegistry> registryProvider) {
		ReactiveAuthorizationManager<MethodInvocationResult> authorizationManager = manager(
				new PostAuthorizeReactiveAuthorizationManager(expressionHandler), registryProvider);
		return AuthorizationManagerAfterReactiveMethodInterceptor.postAuthorize(authorizationManager);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static DefaultMethodSecurityExpressionHandler methodSecurityExpressionHandler(
			@Autowired(required = false) GrantedAuthorityDefaults grantedAuthorityDefaults) {
		DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
		if (grantedAuthorityDefaults != null) {
			handler.setDefaultRolePrefix(grantedAuthorityDefaults.getRolePrefix());
		}
		return handler;
	}

	static <T> ReactiveAuthorizationManager<T> manager(ReactiveAuthorizationManager<T> delegate,
			ObjectProvider<ObservationRegistry> registryProvider) {
		ObservationRegistry registry = registryProvider.getIfAvailable(() -> ObservationRegistry.NOOP);
		if (registry.isNoop()) {
			return delegate;
		}
		return new ObservationReactiveAuthorizationManager<>(registry, delegate);
	}

}
