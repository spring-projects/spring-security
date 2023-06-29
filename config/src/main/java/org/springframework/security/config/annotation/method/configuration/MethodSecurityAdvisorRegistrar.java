/*
 * Copyright 2002-2023 the original author or authors.
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

import org.springframework.aop.Advisor;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.type.AnnotationMetadata;

class MethodSecurityAdvisorRegistrar implements ImportBeanDefinitionRegistrar {

	@Override
	public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry) {
		registerAsAdvisor("preFilterAuthorization", registry);
		registerAsAdvisor("preAuthorizeAuthorization", registry);
		registerAsAdvisor("postFilterAuthorization", registry);
		registerAsAdvisor("postAuthorizeAuthorization", registry);
		registerAsAdvisor("securedAuthorization", registry);
		registerAsAdvisor("jsr250Authorization", registry);
	}

	private void registerAsAdvisor(String prefix, BeanDefinitionRegistry registry) {
		String interceptorName = prefix + "MethodInterceptor";
		if (!registry.containsBeanDefinition(interceptorName)) {
			return;
		}
		BeanDefinition definition = registry.getBeanDefinition(interceptorName);
		if (!(definition instanceof RootBeanDefinition)) {
			return;
		}
		RootBeanDefinition advisor = new RootBeanDefinition((RootBeanDefinition) definition);
		advisor.setTargetType(Advisor.class);
		registry.registerBeanDefinition(prefix + "Advisor", advisor);
	}

}
