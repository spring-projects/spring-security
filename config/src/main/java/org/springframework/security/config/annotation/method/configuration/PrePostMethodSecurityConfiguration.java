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

import org.springframework.aop.Advisor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.PostAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PostFilterAuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.PreAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PreFilterAuthorizationMethodInterceptor;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

/**
 * Base {@link Configuration} for enabling Spring Security Method Security.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.6
 * @see EnableMethodSecurity
 */
@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
final class PrePostMethodSecurityConfiguration {

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static Advisor preFilterAuthorizationMethodInterceptor(ObjectProvider<GrantedAuthorityDefaults> defaultsProvider,
			ObjectProvider<MethodSecurityExpressionHandler> expressionHandlerProvider,
			ObjectProvider<SecurityContextHolderStrategy> strategyProvider, ApplicationContext context) {
		PreFilterAuthorizationMethodInterceptor preFilter = new PreFilterAuthorizationMethodInterceptor();
		strategyProvider.ifAvailable(preFilter::setSecurityContextHolderStrategy);
		preFilter.setExpressionHandler(
				expressionHandlerProvider.getIfAvailable(() -> defaultExpressionHandler(defaultsProvider, context)));
		return preFilter;
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static Advisor preAuthorizeAuthorizationMethodInterceptor(ObjectProvider<GrantedAuthorityDefaults> defaultsProvider,
			ObjectProvider<MethodSecurityExpressionHandler> expressionHandlerProvider,
			ObjectProvider<SecurityContextHolderStrategy> strategyProvider,
			ObjectProvider<AuthorizationEventPublisher> eventPublisherProvider,
			ObjectProvider<ObservationRegistry> registryProvider, ApplicationContext context) {
		PreAuthorizeAuthorizationManager manager = new PreAuthorizeAuthorizationManager();
		manager.setExpressionHandler(
				expressionHandlerProvider.getIfAvailable(() -> defaultExpressionHandler(defaultsProvider, context)));
		AuthorizationManagerBeforeMethodInterceptor preAuthorize = AuthorizationManagerBeforeMethodInterceptor
				.preAuthorize(manager(manager, registryProvider));
		strategyProvider.ifAvailable(preAuthorize::setSecurityContextHolderStrategy);
		eventPublisherProvider.ifAvailable(preAuthorize::setAuthorizationEventPublisher);
		return preAuthorize;
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static Advisor postAuthorizeAuthorizationMethodInterceptor(
			ObjectProvider<GrantedAuthorityDefaults> defaultsProvider,
			ObjectProvider<MethodSecurityExpressionHandler> expressionHandlerProvider,
			ObjectProvider<SecurityContextHolderStrategy> strategyProvider,
			ObjectProvider<AuthorizationEventPublisher> eventPublisherProvider,
			ObjectProvider<ObservationRegistry> registryProvider, ApplicationContext context) {
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		manager.setExpressionHandler(
				expressionHandlerProvider.getIfAvailable(() -> defaultExpressionHandler(defaultsProvider, context)));
		AuthorizationManagerAfterMethodInterceptor postAuthorize = AuthorizationManagerAfterMethodInterceptor
				.postAuthorize(manager(manager, registryProvider));
		strategyProvider.ifAvailable(postAuthorize::setSecurityContextHolderStrategy);
		eventPublisherProvider.ifAvailable(postAuthorize::setAuthorizationEventPublisher);
		return postAuthorize;
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static Advisor postFilterAuthorizationMethodInterceptor(ObjectProvider<GrantedAuthorityDefaults> defaultsProvider,
			ObjectProvider<MethodSecurityExpressionHandler> expressionHandlerProvider,
			ObjectProvider<SecurityContextHolderStrategy> strategyProvider, ApplicationContext context) {
		PostFilterAuthorizationMethodInterceptor postFilter = new PostFilterAuthorizationMethodInterceptor();
		strategyProvider.ifAvailable(postFilter::setSecurityContextHolderStrategy);
		postFilter.setExpressionHandler(
				expressionHandlerProvider.getIfAvailable(() -> defaultExpressionHandler(defaultsProvider, context)));
		return postFilter;
	}

	private static MethodSecurityExpressionHandler defaultExpressionHandler(
			ObjectProvider<GrantedAuthorityDefaults> defaultsProvider, ApplicationContext context) {
		DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
		defaultsProvider.ifAvailable((d) -> handler.setDefaultRolePrefix(d.getRolePrefix()));
		handler.setApplicationContext(context);
		return handler;
	}

	static <T> AuthorizationManager<T> manager(AuthorizationManager<T> delegate,
			ObjectProvider<ObservationRegistry> registryProvider) {
		return new DeferringObservationAuthorizationManager<>(registryProvider, delegate);
	}

}
