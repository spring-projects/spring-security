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

package org.springframework.security.web;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.util.annotation.NonNull;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.BeanNameAware;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.core.log.LogMessage;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

/**
 * Standard implementation of {@code SecurityFilterChain}.
 *
 * @author Luke Taylor
 * @author Jinwoo Bae
 * @since 3.1
 */
public final class DefaultSecurityFilterChain implements SecurityFilterChain, BeanNameAware, BeanFactoryAware {

	private static final Log logger = LogFactory.getLog(DefaultSecurityFilterChain.class);

	private final RequestMatcher requestMatcher;

	private final List<Filter> filters;

	private String beanName;

	private ConfigurableListableBeanFactory beanFactory;

	public DefaultSecurityFilterChain(RequestMatcher requestMatcher, Filter... filters) {
		this(requestMatcher, Arrays.asList(filters));
	}

	public DefaultSecurityFilterChain(RequestMatcher requestMatcher, List<Filter> filters) {
		if (filters.isEmpty()) {
			logger.debug(LogMessage.format("Will not secure %s", requestMatcher));
		}
		else {
			List<String> filterNames = new ArrayList<>();
			for (Filter filter : filters) {
				filterNames.add(filter.getClass().getSimpleName());
			}
			String names = StringUtils.collectionToDelimitedString(filterNames, ", ");
			logger.debug(LogMessage.format("Will secure %s with filters: %s", requestMatcher, names));
		}
		this.requestMatcher = requestMatcher;
		this.filters = new ArrayList<>(filters);
	}

	public RequestMatcher getRequestMatcher() {
		return this.requestMatcher;
	}

	@Override
	public List<Filter> getFilters() {
		return this.filters;
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		return this.requestMatcher.matches(request);
	}

	@Override
	public String toString() {
		List<String> filterNames = new ArrayList<>();
		for (Filter filter : this.filters) {
			String name = filter.getClass().getSimpleName();
			if (name.endsWith("Filter")) {
				name = name.substring(0, name.length() - "Filter".length());
			}
			filterNames.add(name);
		}
		String declaration = this.getClass().getSimpleName();
		if (this.beanName != null) {
			declaration += " defined as '" + this.beanName + "'";
			if (this.beanFactory != null) {
				BeanDefinition bd = this.beanFactory.getBeanDefinition(this.beanName);
				String description = bd.getResourceDescription();
				if (description != null) {
					declaration += " in [" + description + "]";
				}
			}
		}
		return declaration + " matching [" + this.requestMatcher + "] and having filters " + filterNames;
	}

	@Override
	public void setBeanName(@NonNull String name) {
		this.beanName = name;
	}

	@Override
	public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
		if (beanFactory instanceof ConfigurableListableBeanFactory listable) {
			this.beanFactory = listable;
		}
	}

}
