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

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.type.AnnotationMetadata;

/**
 * Registers an
 * {@link org.springframework.aop.aspectj.annotation.AnnotationAwareAspectJAutoProxyCreator
 * AnnotationAwareAspectJAutoProxyCreator} against the current
 * {@link BeanDefinitionRegistry} as appropriate based on a given @
 * {@link EnableMethodSecurity} annotation.
 *
 * <p>
 * Note: This class is necessary because AspectJAutoProxyRegistrar only supports
 * EnableAspectJAutoProxy.
 * </p>
 *
 * @author Josh Cummings
 * @since 5.8
 */
class MethodSecurityAspectJAutoProxyRegistrar implements ImportBeanDefinitionRegistrar {

	/**
	 * Register, escalate, and configure the AspectJ auto proxy creator based on the value
	 * of the @{@link EnableMethodSecurity#proxyTargetClass()} attribute on the importing
	 * {@code @Configuration} class.
	 */
	@Override
	public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry) {
		registerBeanDefinition("preFilterAuthorizationMethodInterceptor",
				"org.springframework.security.authorization.method.aspectj.PreFilterAspect", "preFilterAspect$0",
				registry);
		registerBeanDefinition("postFilterAuthorizationMethodInterceptor",
				"org.springframework.security.authorization.method.aspectj.PostFilterAspect", "postFilterAspect$0",
				registry);
		registerBeanDefinition("preAuthorizeAuthorizationMethodInterceptor",
				"org.springframework.security.authorization.method.aspectj.PreAuthorizeAspect", "preAuthorizeAspect$0",
				registry);
		registerBeanDefinition("postAuthorizeAuthorizationMethodInterceptor",
				"org.springframework.security.authorization.method.aspectj.PostAuthorizeAspect",
				"postAuthorizeAspect$0", registry);
		registerBeanDefinition("securedAuthorizationMethodInterceptor",
				"org.springframework.security.authorization.method.aspectj.SecuredAspect", "securedAspect$0", registry);
	}

	private void registerBeanDefinition(String beanName, String aspectClassName, String aspectBeanName,
			BeanDefinitionRegistry registry) {
		if (!registry.containsBeanDefinition(beanName)) {
			return;
		}
		BeanDefinition interceptor = registry.getBeanDefinition(beanName);
		BeanDefinitionBuilder aspect = BeanDefinitionBuilder.rootBeanDefinition(aspectClassName);
		aspect.setFactoryMethod("aspectOf");
		aspect.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
		aspect.addPropertyValue("securityInterceptor", interceptor);
		registry.registerBeanDefinition(aspectBeanName, aspect.getBeanDefinition());
	}

}
