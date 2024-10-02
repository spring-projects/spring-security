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
import org.springframework.context.annotation.ImportAware;
import org.springframework.context.annotation.Role;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.aot.hint.PrePostAuthorizeHintsRegistrar;
import org.springframework.security.aot.hint.SecurityHintsRegistrar;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.authorization.method.PostAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PostFilterAuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.PreAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PreFilterAuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.PrePostTemplateDefaults;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

/**
 * Base {@link Configuration} for enabling Spring Security Method Security.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.6
 * @see EnableMethodSecurity
 */
@Configuration(value = "_prePostMethodSecurityConfiguration", proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
final class PrePostMethodSecurityConfiguration implements ImportAware, ApplicationContextAware, AopInfrastructureBean {

	private static final Pointcut preFilterPointcut = new PreFilterAuthorizationMethodInterceptor().getPointcut();

	private static final Pointcut preAuthorizePointcut = AuthorizationManagerBeforeMethodInterceptor.preAuthorize()
		.getPointcut();

	private static final Pointcut postAuthorizePointcut = AuthorizationManagerAfterMethodInterceptor.postAuthorize()
		.getPointcut();

	private static final Pointcut postFilterPointcut = new PostFilterAuthorizationMethodInterceptor().getPointcut();

	private final PreAuthorizeAuthorizationManager preAuthorizeAuthorizationManager = new PreAuthorizeAuthorizationManager();

	private final PostAuthorizeAuthorizationManager postAuthorizeAuthorizationManager = new PostAuthorizeAuthorizationManager();

	private final PreFilterAuthorizationMethodInterceptor preFilterMethodInterceptor = new PreFilterAuthorizationMethodInterceptor();

	private final AuthorizationManagerBeforeMethodInterceptor preAuthorizeMethodInterceptor;

	private final AuthorizationManagerAfterMethodInterceptor postAuthorizeMethodInterceptor;

	private final PostFilterAuthorizationMethodInterceptor postFilterMethodInterceptor = new PostFilterAuthorizationMethodInterceptor();

	private final DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();

	PrePostMethodSecurityConfiguration(
			ObjectProvider<ObjectPostProcessor<AuthorizationManager<MethodInvocation>>> preAuthorizeProcessor,
			ObjectProvider<ObjectPostProcessor<AuthorizationManager<MethodInvocationResult>>> postAuthorizeProcessor) {
		this.preFilterMethodInterceptor.setExpressionHandler(this.expressionHandler);
		this.preAuthorizeAuthorizationManager.setExpressionHandler(this.expressionHandler);
		this.postAuthorizeAuthorizationManager.setExpressionHandler(this.expressionHandler);
		this.postFilterMethodInterceptor.setExpressionHandler(this.expressionHandler);
		AuthorizationManager<MethodInvocation> preAuthorize = preAuthorizeProcessor
			.getIfUnique(ObjectPostProcessor::identity)
			.postProcess(this.preAuthorizeAuthorizationManager);
		this.preAuthorizeMethodInterceptor = AuthorizationManagerBeforeMethodInterceptor.preAuthorize(preAuthorize);
		AuthorizationManager<MethodInvocationResult> postAuthorize = postAuthorizeProcessor
			.getIfUnique(ObjectPostProcessor::identity)
			.postProcess(this.postAuthorizeAuthorizationManager);
		this.postAuthorizeMethodInterceptor = AuthorizationManagerAfterMethodInterceptor.postAuthorize(postAuthorize);
	}

	@Override
	public void setApplicationContext(ApplicationContext context) throws BeansException {
		this.expressionHandler.setApplicationContext(context);
		this.preAuthorizeAuthorizationManager.setApplicationContext(context);
		this.postAuthorizeAuthorizationManager.setApplicationContext(context);
	}

	@Autowired(required = false)
	void setGrantedAuthorityDefaults(GrantedAuthorityDefaults grantedAuthorityDefaults) {
		this.expressionHandler.setDefaultRolePrefix(grantedAuthorityDefaults.getRolePrefix());
	}

	@Autowired(required = false)
	void setRoleHierarchy(RoleHierarchy roleHierarchy) {
		this.expressionHandler.setRoleHierarchy(roleHierarchy);
	}

	@Autowired(required = false)
	void setTemplateDefaults(AnnotationTemplateExpressionDefaults templateDefaults) {
		this.preFilterMethodInterceptor.setTemplateDefaults(templateDefaults);
		this.preAuthorizeAuthorizationManager.setTemplateDefaults(templateDefaults);
		this.postAuthorizeAuthorizationManager.setTemplateDefaults(templateDefaults);
		this.postFilterMethodInterceptor.setTemplateDefaults(templateDefaults);
	}

	@Autowired(required = false)
	void setTemplateDefaults(PrePostTemplateDefaults templateDefaults) {
		this.preFilterMethodInterceptor.setTemplateDefaults(templateDefaults);
		this.preAuthorizeAuthorizationManager.setTemplateDefaults(templateDefaults);
		this.postAuthorizeAuthorizationManager.setTemplateDefaults(templateDefaults);
		this.postFilterMethodInterceptor.setTemplateDefaults(templateDefaults);
	}

	@Autowired(required = false)
	void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
		this.preFilterMethodInterceptor.setExpressionHandler(expressionHandler);
		this.preAuthorizeAuthorizationManager.setExpressionHandler(expressionHandler);
		this.postAuthorizeAuthorizationManager.setExpressionHandler(expressionHandler);
		this.postFilterMethodInterceptor.setExpressionHandler(expressionHandler);
	}

	@Autowired(required = false)
	void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		this.preFilterMethodInterceptor.setSecurityContextHolderStrategy(securityContextHolderStrategy);
		this.preAuthorizeMethodInterceptor.setSecurityContextHolderStrategy(securityContextHolderStrategy);
		this.postAuthorizeMethodInterceptor.setSecurityContextHolderStrategy(securityContextHolderStrategy);
		this.postFilterMethodInterceptor.setSecurityContextHolderStrategy(securityContextHolderStrategy);
	}

	@Autowired(required = false)
	void setAuthorizationEventPublisher(AuthorizationEventPublisher publisher) {
		this.preAuthorizeMethodInterceptor.setAuthorizationEventPublisher(publisher);
		this.postAuthorizeMethodInterceptor.setAuthorizationEventPublisher(publisher);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor preFilterAuthorizationMethodInterceptor(
			ObjectProvider<PrePostMethodSecurityConfiguration> _prePostMethodSecurityConfiguration) {
		return new DeferringMethodInterceptor<>(preFilterPointcut,
				() -> _prePostMethodSecurityConfiguration.getObject().preFilterMethodInterceptor);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor preAuthorizeAuthorizationMethodInterceptor(
			ObjectProvider<PrePostMethodSecurityConfiguration> _prePostMethodSecurityConfiguration) {
		return new DeferringMethodInterceptor<>(preAuthorizePointcut,
				() -> _prePostMethodSecurityConfiguration.getObject().preAuthorizeMethodInterceptor);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor postAuthorizeAuthorizationMethodInterceptor(
			ObjectProvider<PrePostMethodSecurityConfiguration> _prePostMethodSecurityConfiguration) {
		return new DeferringMethodInterceptor<>(postAuthorizePointcut,
				() -> _prePostMethodSecurityConfiguration.getObject().postAuthorizeMethodInterceptor);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor postFilterAuthorizationMethodInterceptor(
			ObjectProvider<PrePostMethodSecurityConfiguration> _prePostMethodSecurityConfiguration) {
		return new DeferringMethodInterceptor<>(postFilterPointcut,
				() -> _prePostMethodSecurityConfiguration.getObject().postFilterMethodInterceptor);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static SecurityHintsRegistrar prePostAuthorizeExpressionHintsRegistrar() {
		return new PrePostAuthorizeHintsRegistrar();
	}

	@Override
	public void setImportMetadata(AnnotationMetadata importMetadata) {
		EnableMethodSecurity annotation = importMetadata.getAnnotations().get(EnableMethodSecurity.class).synthesize();
		this.preFilterMethodInterceptor.setOrder(this.preFilterMethodInterceptor.getOrder() + annotation.offset());
		this.preAuthorizeMethodInterceptor
			.setOrder(this.preAuthorizeMethodInterceptor.getOrder() + annotation.offset());
		this.postAuthorizeMethodInterceptor
			.setOrder(this.postAuthorizeMethodInterceptor.getOrder() + annotation.offset());
		this.postFilterMethodInterceptor.setOrder(this.postFilterMethodInterceptor.getOrder() + annotation.offset());
	}

}
