/*
 * Copyright 2012-2018 the original author or authors.
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

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.lang.Nullable;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

/**
 * Used for creating an instance of {@link HandlerMappingIntrospector} and autowiring the
 * {@link ApplicationContext}.
 *
 * @author Rob Winch
 * @since 4.1.1
 */
class HandlerMappingIntrospectorFactoryBean
		implements FactoryBean<HandlerMappingIntrospector>, ApplicationContextAware {

	private static final String HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME = "mvcHandlerMappingIntrospector";

	private ApplicationContext context;

	@Override
	public HandlerMappingIntrospector getObject() {
		if (!this.context.containsBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME)) {
			throw new NoSuchBeanDefinitionException(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME,
					"A Bean named " + HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME + " of type "
							+ HandlerMappingIntrospector.class.getName()
							+ " is required to use MvcRequestMatcher. Please ensure Spring Security & Spring "
							+ "MVC are configured in a shared ApplicationContext.");
		}
		return this.context.getBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME, HandlerMappingIntrospector.class);
	}

	@Nullable
	@Override
	public Class<?> getObjectType() {
		return HandlerMappingIntrospector.class;
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.context = applicationContext;
	}

}
