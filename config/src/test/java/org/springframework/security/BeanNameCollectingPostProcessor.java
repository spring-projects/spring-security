/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;

/**
 * @author Luke Taylor
 */
public class BeanNameCollectingPostProcessor implements BeanPostProcessor {
	Set<String> beforeInitPostProcessedBeans = new HashSet<>();
	Set<String> afterInitPostProcessedBeans = new HashSet<>();

	public Object postProcessBeforeInitialization(Object bean, String beanName)
			throws BeansException {
		if (beanName != null) {
			beforeInitPostProcessedBeans.add(beanName);
		}
		return bean;
	}

	public Object postProcessAfterInitialization(Object bean, String beanName)
			throws BeansException {
		if (beanName != null) {
			afterInitPostProcessedBeans.add(beanName);
		}
		return bean;
	}

	public Set<String> getBeforeInitPostProcessedBeans() {
		return beforeInitPostProcessedBeans;
	}

	public Set<String> getAfterInitPostProcessedBeans() {
		return afterInitPostProcessedBeans;
	}
}
