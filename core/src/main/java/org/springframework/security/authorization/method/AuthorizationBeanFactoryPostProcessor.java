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

package org.springframework.security.authorization.method;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.RootBeanDefinition;

/**
 * Adds {@link AuthorizationBeforeReactiveMethodInterceptor} and
 * {@link AuthorizationAfterReactiveMethodInterceptor} bean definitions to the
 * {@link BeanDefinitionRegistry} if they have not already been added.
 *
 * @author Evgeniy Cheban
 * @since 5.8
 */
final class AuthorizationBeanFactoryPostProcessor implements BeanDefinitionRegistryPostProcessor {

	private static final String BEFORE_INTERCEPTOR_BEAN_NAME = "org.springframework.security.authorization.method.authorizationBeforeReactiveMethodInterceptor";

	private static final String AFTER_INTERCEPTOR_BEAN_NAME = "org.springframework.security.authorization.method.authorizationAfterReactiveMethodInterceptor";

	@Override
	public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) {
		if (!registry.containsBeanDefinition(BEFORE_INTERCEPTOR_BEAN_NAME)) {
			RootBeanDefinition beforeInterceptor = new RootBeanDefinition(
					AuthorizationBeforeReactiveMethodInterceptor.class);
			beforeInterceptor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
			registry.registerBeanDefinition(BEFORE_INTERCEPTOR_BEAN_NAME, beforeInterceptor);
		}
		if (!registry.containsBeanDefinition(AFTER_INTERCEPTOR_BEAN_NAME)) {
			RootBeanDefinition afterInterceptor = new RootBeanDefinition(
					AuthorizationAfterReactiveMethodInterceptor.class);
			afterInterceptor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);
			registry.registerBeanDefinition(AFTER_INTERCEPTOR_BEAN_NAME, afterInterceptor);
		}
	}

	@Override
	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) {
	}

}
