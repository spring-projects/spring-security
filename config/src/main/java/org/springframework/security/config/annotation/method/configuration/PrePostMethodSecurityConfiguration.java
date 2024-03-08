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
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.context.annotation.Role;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.NullRoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationAdvisor;
import org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.PostAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PostFilterAuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.PreAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PreFilterAuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.PrePostTemplateDefaults;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.function.SingletonSupplier;

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
final class PrePostMethodSecurityConfiguration implements ImportAware, AopInfrastructureBean {

	private int interceptorOrderOffset;

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor preFilterAuthorizationMethodInterceptor(
			ObjectProvider<GrantedAuthorityDefaults> defaultsProvider,
			ObjectProvider<PrePostTemplateDefaults> methodSecurityDefaultsProvider,
			ObjectProvider<MethodSecurityExpressionHandler> expressionHandlerProvider,
			ObjectProvider<SecurityContextHolderStrategy> strategyProvider,
			ObjectProvider<RoleHierarchy> roleHierarchyProvider, PrePostMethodSecurityConfiguration configuration,
			ApplicationContext context) {
		PreFilterAuthorizationMethodInterceptor preFilter = new PreFilterAuthorizationMethodInterceptor();
		preFilter.setOrder(preFilter.getOrder() + configuration.interceptorOrderOffset);
		return new DeferringMethodInterceptor<>(preFilter, (f) -> {
			methodSecurityDefaultsProvider.ifAvailable(f::setTemplateDefaults);
			f.setExpressionHandler(expressionHandlerProvider
				.getIfAvailable(() -> defaultExpressionHandler(defaultsProvider, roleHierarchyProvider, context)));
			strategyProvider.ifAvailable(f::setSecurityContextHolderStrategy);
		});
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor preAuthorizeAuthorizationMethodInterceptor(
			ObjectProvider<GrantedAuthorityDefaults> defaultsProvider,
			ObjectProvider<PrePostTemplateDefaults> methodSecurityDefaultsProvider,
			ObjectProvider<MethodSecurityExpressionHandler> expressionHandlerProvider,
			ObjectProvider<SecurityContextHolderStrategy> strategyProvider,
			ObjectProvider<AuthorizationEventPublisher> eventPublisherProvider,
			ObjectProvider<ObservationRegistry> registryProvider, ObjectProvider<RoleHierarchy> roleHierarchyProvider,
			PrePostMethodSecurityConfiguration configuration, ApplicationContext context) {
		PreAuthorizeAuthorizationManager manager = new PreAuthorizeAuthorizationManager();
		manager.setApplicationContext(context);
		AuthorizationManagerBeforeMethodInterceptor preAuthorize = AuthorizationManagerBeforeMethodInterceptor
			.preAuthorize(manager(manager, registryProvider));
		preAuthorize.setOrder(preAuthorize.getOrder() + configuration.interceptorOrderOffset);
		return new DeferringMethodInterceptor<>(preAuthorize, (f) -> {
			methodSecurityDefaultsProvider.ifAvailable(manager::setTemplateDefaults);
			manager.setExpressionHandler(expressionHandlerProvider
				.getIfAvailable(() -> defaultExpressionHandler(defaultsProvider, roleHierarchyProvider, context)));
			strategyProvider.ifAvailable(f::setSecurityContextHolderStrategy);
			eventPublisherProvider.ifAvailable(f::setAuthorizationEventPublisher);
		});
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor postAuthorizeAuthorizationMethodInterceptor(
			ObjectProvider<GrantedAuthorityDefaults> defaultsProvider,
			ObjectProvider<PrePostTemplateDefaults> methodSecurityDefaultsProvider,
			ObjectProvider<MethodSecurityExpressionHandler> expressionHandlerProvider,
			ObjectProvider<SecurityContextHolderStrategy> strategyProvider,
			ObjectProvider<AuthorizationEventPublisher> eventPublisherProvider,
			ObjectProvider<ObservationRegistry> registryProvider, ObjectProvider<RoleHierarchy> roleHierarchyProvider,
			PrePostMethodSecurityConfiguration configuration, ApplicationContext context) {
		PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();
		manager.setApplicationContext(context);
		AuthorizationManagerAfterMethodInterceptor postAuthorize = AuthorizationManagerAfterMethodInterceptor
			.postAuthorize(manager(manager, registryProvider));
		postAuthorize.setOrder(postAuthorize.getOrder() + configuration.interceptorOrderOffset);
		return new DeferringMethodInterceptor<>(postAuthorize, (f) -> {
			methodSecurityDefaultsProvider.ifAvailable(manager::setTemplateDefaults);
			manager.setExpressionHandler(expressionHandlerProvider
				.getIfAvailable(() -> defaultExpressionHandler(defaultsProvider, roleHierarchyProvider, context)));
			strategyProvider.ifAvailable(f::setSecurityContextHolderStrategy);
			eventPublisherProvider.ifAvailable(f::setAuthorizationEventPublisher);
		});
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor postFilterAuthorizationMethodInterceptor(
			ObjectProvider<GrantedAuthorityDefaults> defaultsProvider,
			ObjectProvider<PrePostTemplateDefaults> methodSecurityDefaultsProvider,
			ObjectProvider<MethodSecurityExpressionHandler> expressionHandlerProvider,
			ObjectProvider<SecurityContextHolderStrategy> strategyProvider,
			ObjectProvider<RoleHierarchy> roleHierarchyProvider, PrePostMethodSecurityConfiguration configuration,
			ApplicationContext context) {
		PostFilterAuthorizationMethodInterceptor postFilter = new PostFilterAuthorizationMethodInterceptor();
		postFilter.setOrder(postFilter.getOrder() + configuration.interceptorOrderOffset);
		return new DeferringMethodInterceptor<>(postFilter, (f) -> {
			methodSecurityDefaultsProvider.ifAvailable(f::setTemplateDefaults);
			f.setExpressionHandler(expressionHandlerProvider
				.getIfAvailable(() -> defaultExpressionHandler(defaultsProvider, roleHierarchyProvider, context)));
			strategyProvider.ifAvailable(f::setSecurityContextHolderStrategy);
		});
	}

	private static MethodSecurityExpressionHandler defaultExpressionHandler(
			ObjectProvider<GrantedAuthorityDefaults> defaultsProvider,
			ObjectProvider<RoleHierarchy> roleHierarchyProvider, ApplicationContext context) {
		DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
		RoleHierarchy roleHierarchy = roleHierarchyProvider.getIfAvailable(NullRoleHierarchy::new);
		handler.setRoleHierarchy(roleHierarchy);
		defaultsProvider.ifAvailable((d) -> handler.setDefaultRolePrefix(d.getRolePrefix()));
		handler.setApplicationContext(context);
		return handler;
	}

	static <T> AuthorizationManager<T> manager(AuthorizationManager<T> delegate,
			ObjectProvider<ObservationRegistry> registryProvider) {
		return new DeferringObservationAuthorizationManager<>(registryProvider, delegate);
	}

	@Override
	public void setImportMetadata(AnnotationMetadata importMetadata) {
		EnableMethodSecurity annotation = importMetadata.getAnnotations().get(EnableMethodSecurity.class).synthesize();
		this.interceptorOrderOffset = annotation.offset();
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
