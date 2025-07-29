/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.config.http;

import org.jspecify.annotations.Nullable;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.util.StringUtils;

public final class PathPatternRequestMatcherFactoryBean
		implements FactoryBean<PathPatternRequestMatcher>, ApplicationContextAware, InitializingBean {

	private final String pattern;

	private String basePath;

	private HttpMethod method;

	private PathPatternRequestMatcher.Builder builder;

	PathPatternRequestMatcherFactoryBean(String pattern) {
		this.pattern = pattern;
	}

	PathPatternRequestMatcherFactoryBean(String pattern, String method) {
		this.pattern = pattern;
		this.method = StringUtils.hasText(method) ? HttpMethod.valueOf(method) : null;
	}

	@Override
	public @Nullable PathPatternRequestMatcher getObject() throws Exception {
		return this.builder.matcher(this.method, this.pattern);
	}

	@Override
	public @Nullable Class<?> getObjectType() {
		return PathPatternRequestMatcher.class;
	}

	public void setBasePath(String basePath) {
		this.basePath = basePath;
	}

	@Override
	public void setApplicationContext(ApplicationContext context) throws BeansException {
		this.builder = context.getBeanProvider(PathPatternRequestMatcher.Builder.class)
			.getIfUnique(PathPatternRequestMatcher::withDefaults);
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		if (this.basePath != null) {
			this.builder.basePath(this.basePath);
		}
	}

}
