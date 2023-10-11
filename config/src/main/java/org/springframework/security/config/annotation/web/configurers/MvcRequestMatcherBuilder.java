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

package org.springframework.security.config.annotation.web.configurers;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

final class MvcRequestMatcherBuilder implements RequestMatcherBuilder {

	private static final String HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME = "mvcHandlerMappingIntrospector";

	private final HandlerMappingIntrospector introspector;

	private final ObjectPostProcessor<Object> objectPostProcessor;

	private final String servletPath;

	private MvcRequestMatcherBuilder(ApplicationContext context, String servletPath) {
		if (!context.containsBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME)) {
			throw new NoSuchBeanDefinitionException("A Bean named " + HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME
					+ " of type " + HandlerMappingIntrospector.class.getName()
					+ " is required to use MvcRequestMatcher. Please ensure Spring Security & Spring MVC are configured in a shared ApplicationContext.");
		}
		this.introspector = context.getBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME, HandlerMappingIntrospector.class);
		this.objectPostProcessor = context.getBean(ObjectPostProcessor.class);
		this.servletPath = servletPath;
	}

	static MvcRequestMatcherBuilder absolute(ApplicationContext context) {
		return new MvcRequestMatcherBuilder(context, null);
	}

	static MvcRequestMatcherBuilder relativeTo(ApplicationContext context, String path) {
		return new MvcRequestMatcherBuilder(context, path);
	}

	@Override
	public MvcRequestMatcher matcher(String pattern) {
		MvcRequestMatcher matcher = new MvcRequestMatcher(this.introspector, pattern);
		this.objectPostProcessor.postProcess(matcher);
		if (this.servletPath != null) {
			matcher.setServletPath(this.servletPath);
		}
		return matcher;
	}

	@Override
	public MvcRequestMatcher matcher(HttpMethod method, String pattern) {
		MvcRequestMatcher matcher = new MvcRequestMatcher(this.introspector, pattern);
		this.objectPostProcessor.postProcess(matcher);
		matcher.setMethod(method);
		if (this.servletPath != null) {
			matcher.setServletPath(this.servletPath);
		}
		return matcher;
	}

}
