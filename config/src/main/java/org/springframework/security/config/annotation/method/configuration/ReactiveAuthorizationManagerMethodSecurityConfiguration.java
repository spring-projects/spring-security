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

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.Pointcut;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Fallback;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerAfterReactiveMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeReactiveMethodInterceptor;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.authorization.method.PostAuthorizeReactiveAuthorizationManager;
import org.springframework.security.authorization.method.PostFilterAuthorizationReactiveMethodInterceptor;
import org.springframework.security.authorization.method.PreAuthorizeReactiveAuthorizationManager;
import org.springframework.security.authorization.method.PreFilterAuthorizationReactiveMethodInterceptor;
import org.springframework.security.authorization.method.PrePostTemplateDefaults;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;

/**
 * Configuration for a {@link ReactiveAuthenticationManager} based Method Security.
 *
 * @author Evgeniy Cheban
 * @since 5.8
 */
@Configuration(value = "_reactiveMethodSecurityConfiguration", proxyBeanMethods = false)
final class ReactiveAuthorizationManagerMethodSecurityConfiguration
		implements AopInfrastructureBean, ApplicationContextAware {

	private static final Pointcut preFilterPointcut = new PreFilterAuthorizationReactiveMethodInterceptor()
		.getPointcut();

	private static final Pointcut preAuthorizePointcut = AuthorizationManagerBeforeReactiveMethodInterceptor
		.preAuthorize()
		.getPointcut();

	private static final Pointcut postAuthorizePointcut = AuthorizationManagerAfterReactiveMethodInterceptor
		.postAuthorize()
		.getPointcut();

	private static final Pointcut postFilterPointcut = new PostFilterAuthorizationReactiveMethodInterceptor()
		.getPointcut();

	private PreFilterAuthorizationReactiveMethodInterceptor preFilterMethodInterceptor = new PreFilterAuthorizationReactiveMethodInterceptor();

	private PreAuthorizeReactiveAuthorizationManager preAuthorizeAuthorizationManager = new PreAuthorizeReactiveAuthorizationManager();

	private PostAuthorizeReactiveAuthorizationManager postAuthorizeAuthorizationManager = new PostAuthorizeReactiveAuthorizationManager();

	private PostFilterAuthorizationReactiveMethodInterceptor postFilterMethodInterceptor = new PostFilterAuthorizationReactiveMethodInterceptor();

	private final AuthorizationManagerBeforeReactiveMethodInterceptor preAuthorizeMethodInterceptor;

	private final AuthorizationManagerAfterReactiveMethodInterceptor postAuthorizeMethodInterceptor;

	@Autowired(required = false)
	ReactiveAuthorizationManagerMethodSecurityConfiguration(MethodSecurityExpressionHandler expressionHandler,
			ObjectProvider<ObjectPostProcessor<ReactiveAuthorizationManager<MethodInvocation>>> preAuthorizePostProcessor,
			ObjectProvider<ObjectPostProcessor<ReactiveAuthorizationManager<MethodInvocationResult>>> postAuthorizePostProcessor) {
		if (expressionHandler != null) {
			this.preFilterMethodInterceptor = new PreFilterAuthorizationReactiveMethodInterceptor(expressionHandler);
			this.preAuthorizeAuthorizationManager = new PreAuthorizeReactiveAuthorizationManager(expressionHandler);
			this.postFilterMethodInterceptor = new PostFilterAuthorizationReactiveMethodInterceptor(expressionHandler);
			this.postAuthorizeAuthorizationManager = new PostAuthorizeReactiveAuthorizationManager(expressionHandler);
		}
		ReactiveAuthorizationManager<MethodInvocation> preAuthorize = preAuthorizePostProcessor
			.getIfUnique(ObjectPostProcessor::identity)
			.postProcess(this.preAuthorizeAuthorizationManager);
		this.preAuthorizeMethodInterceptor = AuthorizationManagerBeforeReactiveMethodInterceptor
			.preAuthorize(preAuthorize);
		ReactiveAuthorizationManager<MethodInvocationResult> postAuthorize = postAuthorizePostProcessor
			.getIfAvailable(ObjectPostProcessor::identity)
			.postProcess(this.postAuthorizeAuthorizationManager);
		this.postAuthorizeMethodInterceptor = AuthorizationManagerAfterReactiveMethodInterceptor
			.postAuthorize(postAuthorize);
	}

	@Override
	public void setApplicationContext(ApplicationContext context) throws BeansException {
		this.preAuthorizeAuthorizationManager.setApplicationContext(context);
		this.postAuthorizeAuthorizationManager.setApplicationContext(context);
	}

	@Autowired(required = false)
	void setTemplateDefaults(PrePostTemplateDefaults templateDefaults) {
		this.preFilterMethodInterceptor.setTemplateDefaults(templateDefaults);
		this.preAuthorizeAuthorizationManager.setTemplateDefaults(templateDefaults);
		this.postAuthorizeAuthorizationManager.setTemplateDefaults(templateDefaults);
		this.postFilterMethodInterceptor.setTemplateDefaults(templateDefaults);
	}

	@Autowired(required = false)
	void setTemplateDefaults(AnnotationTemplateExpressionDefaults templateDefaults) {
		this.preFilterMethodInterceptor.setTemplateDefaults(templateDefaults);
		this.preAuthorizeAuthorizationManager.setTemplateDefaults(templateDefaults);
		this.postAuthorizeAuthorizationManager.setTemplateDefaults(templateDefaults);
		this.postFilterMethodInterceptor.setTemplateDefaults(templateDefaults);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor preFilterAuthorizationMethodInterceptor(
			ObjectProvider<ReactiveAuthorizationManagerMethodSecurityConfiguration> _reactiveMethodSecurityConfiguration) {
		return new DeferringMethodInterceptor<>(preFilterPointcut,
				() -> _reactiveMethodSecurityConfiguration.getObject().preFilterMethodInterceptor);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor preAuthorizeAuthorizationMethodInterceptor(
			ObjectProvider<ReactiveAuthorizationManagerMethodSecurityConfiguration> _reactiveMethodSecurityConfiguration) {
		return new DeferringMethodInterceptor<>(preAuthorizePointcut,
				() -> _reactiveMethodSecurityConfiguration.getObject().preAuthorizeMethodInterceptor);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor postFilterAuthorizationMethodInterceptor(
			ObjectProvider<ReactiveAuthorizationManagerMethodSecurityConfiguration> _reactiveMethodSecurityConfiguration) {
		return new DeferringMethodInterceptor<>(postFilterPointcut,
				() -> _reactiveMethodSecurityConfiguration.getObject().postFilterMethodInterceptor);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor postAuthorizeAuthorizationMethodInterceptor(
			ObjectProvider<ReactiveAuthorizationManagerMethodSecurityConfiguration> _reactiveMethodSecurityConfiguration) {
		return new DeferringMethodInterceptor<>(postAuthorizePointcut,
				() -> _reactiveMethodSecurityConfiguration.getObject().postAuthorizeMethodInterceptor);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	@Fallback
	static DefaultMethodSecurityExpressionHandler methodSecurityExpressionHandler(
			@Autowired(required = false) GrantedAuthorityDefaults grantedAuthorityDefaults) {
		DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
		if (grantedAuthorityDefaults != null) {
			handler.setDefaultRolePrefix(grantedAuthorityDefaults.getRolePrefix());
		}
		return handler;
	}

}
