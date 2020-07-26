/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.config.annotation.web.configuration;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.Filter;

import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.util.Assert;

/**
 * A class used to get all the {@link WebSecurityConfigurer} instances from the current
 * {@link ApplicationContext} but ignoring the parent.
 *
 * @author Rob Winch
 *
 */
final class AutowiredWebSecurityConfigurersIgnoreParents {

	private final ConfigurableListableBeanFactory beanFactory;

	AutowiredWebSecurityConfigurersIgnoreParents(ConfigurableListableBeanFactory beanFactory) {
		Assert.notNull(beanFactory, "beanFactory cannot be null");
		this.beanFactory = beanFactory;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public List<SecurityConfigurer<Filter, WebSecurity>> getWebSecurityConfigurers() {
		List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers = new ArrayList<>();
		Map<String, WebSecurityConfigurer> beansOfType = this.beanFactory.getBeansOfType(WebSecurityConfigurer.class);
		for (Entry<String, WebSecurityConfigurer> entry : beansOfType.entrySet()) {
			webSecurityConfigurers.add(entry.getValue());
		}
		return webSecurityConfigurers;
	}

}
