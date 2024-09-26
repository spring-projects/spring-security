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

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.Aware;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.core.NativeDetector;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.util.Assert;

/**
 * Allows registering Objects to participate with an {@link AutowireCapableBeanFactory}'s
 * post processing of {@link Aware} methods, {@link InitializingBean#afterPropertiesSet()}
 * , and {@link DisposableBean#destroy()}.
 *
 * @author Rob Winch
 * @since 3.2
 */
final class AutowireBeanFactoryObjectPostProcessor
		implements ObjectPostProcessor<Object>, DisposableBean, SmartInitializingSingleton {

	private final Log logger = LogFactory.getLog(getClass());

	private final AutowireCapableBeanFactory autowireBeanFactory;

	private final List<DisposableBean> disposableBeans = new ArrayList<>();

	private final List<SmartInitializingSingleton> smartSingletons = new ArrayList<>();

	AutowireBeanFactoryObjectPostProcessor(AutowireCapableBeanFactory autowireBeanFactory) {
		Assert.notNull(autowireBeanFactory, "autowireBeanFactory cannot be null");
		this.autowireBeanFactory = autowireBeanFactory;
	}

	@Override
	public <T> T postProcess(T object) {
		if (object == null) {
			return null;
		}
		T result = null;
		try {
			result = initializeBeanIfNeeded(object);
		}
		catch (RuntimeException ex) {
			Class<?> type = object.getClass();
			throw new RuntimeException("Could not postProcess " + object + " of type " + type, ex);
		}
		this.autowireBeanFactory.autowireBean(object);
		if (result instanceof DisposableBean) {
			this.disposableBeans.add((DisposableBean) result);
		}
		if (result instanceof SmartInitializingSingleton) {
			this.smartSingletons.add((SmartInitializingSingleton) result);
		}
		return result;
	}

	/**
	 * Invokes {@link AutowireCapableBeanFactory#initializeBean(Object, String)} only if
	 * needed, i.e when the application is not a native image or the object is not a CGLIB
	 * proxy.
	 * @param object the object to initialize
	 * @param <T> the type of the object
	 * @return the initialized bean or an existing bean if the object is a CGLIB proxy and
	 * the application is a native image
	 * @see <a href=
	 * "https://github.com/spring-projects/spring-security/issues/14825">Issue
	 * gh-14825</a>
	 */
	@SuppressWarnings("unchecked")
	private <T> T initializeBeanIfNeeded(T object) {
		if (!NativeDetector.inNativeImage() || !AopUtils.isCglibProxy(object)) {
			return (T) this.autowireBeanFactory.initializeBean(object, object.toString());
		}
		ObjectProvider<?> provider = this.autowireBeanFactory.getBeanProvider(object.getClass());
		Object bean = provider.getIfUnique();
		if (bean == null) {
			String msg = """
					Failed to resolve an unique bean (single or primary) of type [%s] from the BeanFactory.
					Because the object is a CGLIB Proxy, a raw bean cannot be initialized during runtime in a native image.
					"""
				.formatted(object.getClass());
			throw new IllegalStateException(msg);
		}
		return (T) bean;
	}

	@Override
	public void afterSingletonsInstantiated() {
		for (SmartInitializingSingleton singleton : this.smartSingletons) {
			singleton.afterSingletonsInstantiated();
		}
	}

	@Override
	public void destroy() {
		for (DisposableBean disposable : this.disposableBeans) {
			try {
				disposable.destroy();
			}
			catch (Exception ex) {
				this.logger.error(ex);
			}
		}
	}

}
