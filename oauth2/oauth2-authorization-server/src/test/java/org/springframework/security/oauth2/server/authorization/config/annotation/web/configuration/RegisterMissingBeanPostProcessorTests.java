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

import java.util.function.Supplier;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.endsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link RegisterMissingBeanPostProcessor}.
 *
 * @author Steve Riesenberg
 */
public class RegisterMissingBeanPostProcessorTests {

	private final RegisterMissingBeanPostProcessor postProcessor = new RegisterMissingBeanPostProcessor();

	@Test
	public void postProcessBeanDefinitionRegistryWhenClassAddedThenRegisteredWithClass() {
		this.postProcessor.addBeanDefinition(SimpleBean.class, null);
		this.postProcessor.setBeanFactory(new DefaultListableBeanFactory());

		BeanDefinitionRegistry beanDefinitionRegistry = mock(BeanDefinitionRegistry.class);
		this.postProcessor.postProcessBeanDefinitionRegistry(beanDefinitionRegistry);

		ArgumentCaptor<BeanDefinition> beanDefinitionCaptor = ArgumentCaptor.forClass(BeanDefinition.class);
		verify(beanDefinitionRegistry).registerBeanDefinition(endsWith("SimpleBean"), beanDefinitionCaptor.capture());

		RootBeanDefinition beanDefinition = (RootBeanDefinition) beanDefinitionCaptor.getValue();
		assertThat(beanDefinition.getBeanClass()).isEqualTo(SimpleBean.class);
		assertThat(beanDefinition.getInstanceSupplier()).isNull();
	}

	@Test
	public void postProcessBeanDefinitionRegistryWhenSupplierAddedThenRegisteredWithSupplier() {
		Supplier<SimpleBean> beanSupplier = () -> new SimpleBean("string");
		this.postProcessor.addBeanDefinition(SimpleBean.class, beanSupplier);
		this.postProcessor.setBeanFactory(new DefaultListableBeanFactory());

		BeanDefinitionRegistry beanDefinitionRegistry = mock(BeanDefinitionRegistry.class);
		this.postProcessor.postProcessBeanDefinitionRegistry(beanDefinitionRegistry);

		ArgumentCaptor<BeanDefinition> beanDefinitionCaptor = ArgumentCaptor.forClass(BeanDefinition.class);
		verify(beanDefinitionRegistry).registerBeanDefinition(endsWith("SimpleBean"), beanDefinitionCaptor.capture());

		RootBeanDefinition beanDefinition = (RootBeanDefinition) beanDefinitionCaptor.getValue();
		assertThat(beanDefinition.getBeanClass()).isEqualTo(SimpleBean.class);
		assertThat(beanDefinition.getInstanceSupplier()).isEqualTo(beanSupplier);
	}

	@Test
	public void postProcessBeanDefinitionRegistryWhenNoBeanDefinitionsAddedThenNoneRegistered() {
		this.postProcessor.setBeanFactory(new DefaultListableBeanFactory());

		BeanDefinitionRegistry beanDefinitionRegistry = mock(BeanDefinitionRegistry.class);
		this.postProcessor.postProcessBeanDefinitionRegistry(beanDefinitionRegistry);
		verifyNoInteractions(beanDefinitionRegistry);
	}

	@Test
	public void postProcessBeanDefinitionRegistryWhenBeanDefinitionAlreadyExistsThenNoneRegistered() {
		this.postProcessor.addBeanDefinition(SimpleBean.class, null);
		DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
		beanFactory.registerBeanDefinition("simpleBean", new RootBeanDefinition(SimpleBean.class));
		this.postProcessor.setBeanFactory(beanFactory);

		BeanDefinitionRegistry beanDefinitionRegistry = mock(BeanDefinitionRegistry.class);
		this.postProcessor.postProcessBeanDefinitionRegistry(beanDefinitionRegistry);
		verifyNoInteractions(beanDefinitionRegistry);
	}

	private static final class SimpleBean {

		private final String field;

		private SimpleBean(String field) {
			this.field = field;
		}

		private String getField() {
			return this.field;
		}

	}

}
