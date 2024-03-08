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

import java.util.function.Consumer;
import java.util.function.Supplier;

import io.micrometer.observation.ObservationRegistry;
import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import org.springframework.aop.Pointcut;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.security.authorization.method.AuthorizationManagerAfterReactiveMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeReactiveMethodInterceptor;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.authorization.method.PostAuthorizeReactiveAuthorizationManager;
import org.springframework.security.authorization.method.PostFilterAuthorizationReactiveMethodInterceptor;
import org.springframework.security.authorization.method.PreAuthorizeReactiveAuthorizationManager;
import org.springframework.security.authorization.method.PreFilterAuthorizationReactiveMethodInterceptor;
import org.springframework.security.authorization.method.PrePostTemplateDefaults;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.util.function.SingletonSupplier;

/**
 * Configuration for a {@link ReactiveAuthenticationManager} based Method Security.
 *
 * @author Evgeniy Cheban
 * @since 5.8
 */
@Configuration(proxyBeanMethods = false)
final class ReactiveAuthorizationManagerMethodSecurityConfiguration implements AopInfrastructureBean {

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor preFilterAuthorizationMethodInterceptor(MethodSecurityExpressionHandler expressionHandler,
			ObjectProvider<PrePostTemplateDefaults> defaultsObjectProvider) {
		PreFilterAuthorizationReactiveMethodInterceptor interceptor = new PreFilterAuthorizationReactiveMethodInterceptor(
				expressionHandler);
		return new DeferringMethodInterceptor<>(interceptor,
				(i) -> defaultsObjectProvider.ifAvailable(i::setTemplateDefaults));
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor preAuthorizeAuthorizationMethodInterceptor(
			MethodSecurityExpressionHandler expressionHandler,
			ObjectProvider<PrePostTemplateDefaults> defaultsObjectProvider,
			ObjectProvider<ObservationRegistry> registryProvider, ApplicationContext context) {
		PreAuthorizeReactiveAuthorizationManager manager = new PreAuthorizeReactiveAuthorizationManager(
				expressionHandler);
		manager.setApplicationContext(context);
		ReactiveAuthorizationManager<MethodInvocation> authorizationManager = manager(manager, registryProvider);
		AuthorizationAdvisor interceptor = AuthorizationManagerBeforeReactiveMethodInterceptor
			.preAuthorize(authorizationManager);
		return new DeferringMethodInterceptor<>(interceptor,
				(i) -> defaultsObjectProvider.ifAvailable(manager::setTemplateDefaults));
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor postFilterAuthorizationMethodInterceptor(MethodSecurityExpressionHandler expressionHandler,
			ObjectProvider<PrePostTemplateDefaults> defaultsObjectProvider) {
		PostFilterAuthorizationReactiveMethodInterceptor interceptor = new PostFilterAuthorizationReactiveMethodInterceptor(
				expressionHandler);
		return new DeferringMethodInterceptor<>(interceptor,
				(i) -> defaultsObjectProvider.ifAvailable(i::setTemplateDefaults));
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor postAuthorizeAuthorizationMethodInterceptor(
			MethodSecurityExpressionHandler expressionHandler,
			ObjectProvider<PrePostTemplateDefaults> defaultsObjectProvider,
			ObjectProvider<ObservationRegistry> registryProvider, ApplicationContext context) {
		PostAuthorizeReactiveAuthorizationManager manager = new PostAuthorizeReactiveAuthorizationManager(
				expressionHandler);
		manager.setApplicationContext(context);
		ReactiveAuthorizationManager<MethodInvocationResult> authorizationManager = manager(manager, registryProvider);
		AuthorizationAdvisor interceptor = AuthorizationManagerAfterReactiveMethodInterceptor
			.postAuthorize(authorizationManager);
		return new DeferringMethodInterceptor<>(interceptor,
				(i) -> defaultsObjectProvider.ifAvailable(manager::setTemplateDefaults));
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
		return new DeferringObservationReactiveAuthorizationManager<>(registryProvider, delegate);
	}

	private static final class DeferringMethodInterceptor<M extends AuthorizationAdvisor>
			implements AuthorizationAdvisor {

		private final Pointcut pointcut;

		private final int order;

		private final Supplier<M> delegate;

		DeferringMethodInterceptor(M delegate, Consumer<M> supplier) {
			this.pointcut = delegate.getPointcut();
			this.order = delegate.getOrder();
			this.delegate = SingletonSupplier.of(() -> {
				supplier.accept(delegate);
				return delegate;
			});
		}

		@Nullable
		@Override
		public Object invoke(@NotNull MethodInvocation invocation) throws Throwable {
			return this.delegate.get().invoke(invocation);
		}

		@Override
		public Pointcut getPointcut() {
			return this.pointcut;
		}

		@Override
		public Advice getAdvice() {
			return this;
		}

		@Override
		public int getOrder() {
			return this.order;
		}

		@Override
		public boolean isPerInstance() {
			return true;
		}

	}

}
