/*
 * Copyright 2020-2022 the original author or authors.
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

package org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.annotation.AnnotationBeanNameGenerator;

/**
 * Post processor to register one or more bean definitions on container initialization, if
 * not already present.
 *
 * @author Steve Riesenberg
 * @since 0.2.0
 */
final class RegisterMissingBeanPostProcessor implements BeanDefinitionRegistryPostProcessor, BeanFactoryAware {

	private final AnnotationBeanNameGenerator beanNameGenerator = new AnnotationBeanNameGenerator();

	private final List<AbstractBeanDefinition> beanDefinitions = new ArrayList<>();

	private BeanFactory beanFactory;

	@Override
	public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
		for (AbstractBeanDefinition beanDefinition : this.beanDefinitions) {
			String[] beanNames = BeanFactoryUtils.beanNamesForTypeIncludingAncestors(
					(ListableBeanFactory) this.beanFactory, beanDefinition.getBeanClass(), false, false);
			if (beanNames.length == 0) {
				String beanName = this.beanNameGenerator.generateBeanName(beanDefinition, registry);
				registry.registerBeanDefinition(beanName, beanDefinition);
			}
		}
	}

	@Override
	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
	}

	<T> void addBeanDefinition(Class<T> beanClass, Supplier<T> beanSupplier) {
		this.beanDefinitions.add(new RootBeanDefinition(beanClass, beanSupplier));
	}

	@Override
	public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
		this.beanFactory = beanFactory;
	}

}
