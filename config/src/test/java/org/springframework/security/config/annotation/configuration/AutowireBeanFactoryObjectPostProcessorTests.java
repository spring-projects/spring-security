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

package org.springframework.security.config.annotation.configuration;

import java.lang.reflect.Modifier;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.BeanClassLoaderAware;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.NativeDetector;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.web.context.ServletContextAware;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatException;
import static org.mockito.ArgumentMatchers.isNotNull;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 */
@ExtendWith(SpringTestContextExtension.class)
public class AutowireBeanFactoryObjectPostProcessorTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private ObjectPostProcessor<Object> objectObjectPostProcessor;

	@Test
	public void postProcessWhenApplicationContextAwareThenAwareInvoked() {
		this.spring.register(Config.class).autowire();
		ApplicationContextAware toPostProcess = mock(ApplicationContextAware.class);
		this.objectObjectPostProcessor.postProcess(toPostProcess);
		verify(toPostProcess).setApplicationContext(isNotNull());
	}

	@Test
	public void postProcessWhenApplicationEventPublisherAwareThenAwareInvoked() {
		this.spring.register(Config.class).autowire();
		ApplicationEventPublisherAware toPostProcess = mock(ApplicationEventPublisherAware.class);
		this.objectObjectPostProcessor.postProcess(toPostProcess);
		verify(toPostProcess).setApplicationEventPublisher(isNotNull());
	}

	@Test
	public void postProcessWhenBeanClassLoaderAwareThenAwareInvoked() {
		this.spring.register(Config.class).autowire();
		BeanClassLoaderAware toPostProcess = mock(BeanClassLoaderAware.class);
		this.objectObjectPostProcessor.postProcess(toPostProcess);
		verify(toPostProcess).setBeanClassLoader(isNotNull());
	}

	@Test
	public void postProcessWhenBeanFactoryAwareThenAwareInvoked() {
		this.spring.register(Config.class).autowire();
		BeanFactoryAware toPostProcess = mock(BeanFactoryAware.class);
		this.objectObjectPostProcessor.postProcess(toPostProcess);
		verify(toPostProcess).setBeanFactory(isNotNull());
	}

	@Test
	public void postProcessWhenEnvironmentAwareThenAwareInvoked() {
		this.spring.register(Config.class).autowire();
		EnvironmentAware toPostProcess = mock(EnvironmentAware.class);
		this.objectObjectPostProcessor.postProcess(toPostProcess);
		verify(toPostProcess).setEnvironment(isNotNull());
	}

	@Test
	public void postProcessWhenMessageSourceAwareThenAwareInvoked() {
		this.spring.register(Config.class).autowire();
		MessageSourceAware toPostProcess = mock(MessageSourceAware.class);
		this.objectObjectPostProcessor.postProcess(toPostProcess);
		verify(toPostProcess).setMessageSource(isNotNull());
	}

	@Test
	public void postProcessWhenServletContextAwareThenAwareInvoked() {
		this.spring.register(Config.class).autowire();
		ServletContextAware toPostProcess = mock(ServletContextAware.class);
		this.objectObjectPostProcessor.postProcess(toPostProcess);
		verify(toPostProcess).setServletContext(isNotNull());
	}

	@Test
	public void postProcessWhenDisposableBeanThenAwareInvoked() throws Exception {
		this.spring.register(Config.class).autowire();
		DisposableBean toPostProcess = mock(DisposableBean.class);
		this.objectObjectPostProcessor.postProcess(toPostProcess);
		this.spring.getContext().close();
		verify(toPostProcess).destroy();
	}

	@Test
	public void postProcessWhenSmartInitializingSingletonThenAwareInvoked() {
		this.spring.register(Config.class, SmartConfig.class).autowire();
		SmartConfig config = this.spring.getContext().getBean(SmartConfig.class);
		verify(config.toTest).afterSingletonsInstantiated();
	}

	@Test
	// SEC-2382
	public void autowireBeanFactoryWhenBeanNameAutoProxyCreatorThenWorks() {
		this.spring.testConfigLocations("AutowireBeanFactoryObjectPostProcessorTests-aopconfig.xml").autowire();
		MyAdvisedBean bean = this.spring.getContext().getBean(MyAdvisedBean.class);
		assertThat(bean.doStuff()).isEqualTo("null");
	}

	@Test
	void postProcessWhenObjectIsCgLibProxyAndInNativeImageThenUseExistingBean() {
		try (MockedStatic<NativeDetector> detector = Mockito.mockStatic(NativeDetector.class)) {
			given(NativeDetector.inNativeImage()).willReturn(true);

			ProxyFactory proxyFactory = new ProxyFactory(new MyClass());
			proxyFactory.setProxyTargetClass(!Modifier.isFinal(MyClass.class.getModifiers()));
			MyClass myClass = (MyClass) proxyFactory.getProxy();

			this.spring.register(Config.class, myClass.getClass()).autowire();
			this.spring.getContext().getBean(myClass.getClass()).setIdentifier("0000");

			MyClass postProcessed = this.objectObjectPostProcessor.postProcess(myClass);
			assertThat(postProcessed.getIdentifier()).isEqualTo("0000");
		}
	}

	@Test
	void postProcessWhenObjectIsCgLibProxyAndInNativeImageAndBeanDoesNotExistsThenIllegalStateException() {
		try (MockedStatic<NativeDetector> detector = Mockito.mockStatic(NativeDetector.class)) {
			given(NativeDetector.inNativeImage()).willReturn(true);

			ProxyFactory proxyFactory = new ProxyFactory(new MyClass());
			proxyFactory.setProxyTargetClass(!Modifier.isFinal(MyClass.class.getModifiers()));
			MyClass myClass = (MyClass) proxyFactory.getProxy();

			this.spring.register(Config.class).autowire();

			assertThatException().isThrownBy(() -> this.objectObjectPostProcessor.postProcess(myClass))
				.havingRootCause()
				.isInstanceOf(IllegalStateException.class)
				.withMessage(
						"""
								Failed to resolve an unique bean (single or primary) of type [class org.springframework.security.config.annotation.configuration.AutowireBeanFactoryObjectPostProcessorTests$MyClass$$SpringCGLIB$$0] from the BeanFactory.
								Because the object is a CGLIB Proxy, a raw bean cannot be initialized during runtime in a native image.
								""");
		}
	}

	static class MyClass {

		private String identifier = "1234";

		String getIdentifier() {
			return this.identifier;
		}

		void setIdentifier(String identifier) {
			this.identifier = identifier;
		}

	}

	@Configuration
	static class Config {

		@Bean
		ObjectPostProcessor objectPostProcessor(AutowireCapableBeanFactory beanFactory) {
			return new AutowireBeanFactoryObjectPostProcessor(beanFactory);
		}

	}

	@Configuration
	static class SmartConfig {

		SmartInitializingSingleton toTest = mock(SmartInitializingSingleton.class);

		@Autowired
		void configure(ObjectPostProcessor<Object> p) {
			p.postProcess(this.toTest);
		}

	}

	@Configuration
	static class WithBeanNameAutoProxyCreatorConfig {

		@Bean
		ObjectPostProcessor objectPostProcessor(AutowireCapableBeanFactory beanFactory) {
			return new AutowireBeanFactoryObjectPostProcessor(beanFactory);
		}

		@Autowired
		void configure(ObjectPostProcessor<Object> p) {
			p.postProcess(new Object());
		}

	}

}
