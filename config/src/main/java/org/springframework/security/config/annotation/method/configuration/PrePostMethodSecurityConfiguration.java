/*
 * Copyright 2004-present the original author or authors.
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

import java.util.Map;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.aop.Pointcut;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.context.annotation.Role;
import org.springframework.core.annotation.AnnotationUtils;
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
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.util.ClassUtils;

/**
 * Base {@link Configuration} for enabling Spring Security Method Security.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @author Yoobin Yoon
 * @since 5.6
 * @see EnableMethodSecurity
 */
@Configuration(value = "_prePostMethodSecurityConfiguration", proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
final class PrePostMethodSecurityConfiguration
		implements ImportAware, ApplicationContextAware, AopInfrastructureBean, SmartInitializingSingleton {

	private static final Log logger = LogFactory.getLog(PrePostMethodSecurityConfiguration.class);

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

	private ApplicationContext applicationContext;

	private boolean prePostEnabled = true;

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
		this.applicationContext = context;
		this.expressionHandler.setApplicationContext(context);
		this.preAuthorizeAuthorizationManager.setApplicationContext(context);
		this.postAuthorizeAuthorizationManager.setApplicationContext(context);
	}

	@Override
	public void afterSingletonsInstantiated() {
		if (!this.prePostEnabled) {
			return;
		}
		validateTransactionManagementPrecedence();
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
		this.prePostEnabled = annotation.prePostEnabled();
		this.preFilterMethodInterceptor.setOrder(this.preFilterMethodInterceptor.getOrder() + annotation.offset());
		this.preAuthorizeMethodInterceptor
			.setOrder(this.preAuthorizeMethodInterceptor.getOrder() + annotation.offset());
		this.postAuthorizeMethodInterceptor
			.setOrder(this.postAuthorizeMethodInterceptor.getOrder() + annotation.offset());
		this.postFilterMethodInterceptor.setOrder(this.postFilterMethodInterceptor.getOrder() + annotation.offset());
	}

	/**
	 * Validates that @EnableTransactionManagement has higher precedence
	 * than @EnableMethodSecurity. This is important to ensure that @PostAuthorize checks
	 * happen before transaction commit, allowing rollback on authorization failures.
	 */
	private void validateTransactionManagementPrecedence() {
		try {
			int currentMethodSecurityOrder = this.preAuthorizeMethodInterceptor.getOrder();

			Map<String, Object> txMgmtBeans = this.applicationContext
				.getBeansWithAnnotation(EnableTransactionManagement.class);

			for (Map.Entry<String, Object> entry : txMgmtBeans.entrySet()) {
				Class<?> configClass = ClassUtils.getUserClass(entry.getValue().getClass());
				EnableTransactionManagement txMgmt = AnnotationUtils.findAnnotation(configClass,
						EnableTransactionManagement.class);

				if (txMgmt != null) {
					int txOrder = txMgmt.order();
					if (txOrder >= currentMethodSecurityOrder) {
						logger.warn("@EnableTransactionManagement has same or lower precedence (order=" + txOrder
								+ ") than @EnableMethodSecurity (effective order=" + currentMethodSecurityOrder
								+ "). This may cause issues with @PostAuthorize on methods with side effects. "
								+ "Consider setting @EnableTransactionManagement(order = 0) or adjusting the order values. "
								+ "See Spring Security migration guide for more details.");
						break;
					}
				}
			}
		}
		catch (BeansException ex) {
			logger.warn("Could not validate transaction management precedence due to bean access issues", ex);
		}
		catch (Exception ex) {
			logger.debug("Could not validate transaction management precedence", ex);
		}
	}

}
