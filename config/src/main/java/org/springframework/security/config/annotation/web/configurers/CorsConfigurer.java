/*
 * Copyright 2002-2018 the original author or authors.
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
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.ClassUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

/**
 * Adds {@link CorsFilter} to the Spring Security filter chain. If a bean by the name of
 * corsFilter is provided, that {@link CorsFilter} is used. Else if
 * corsConfigurationSource is defined, then that {@link CorsConfiguration} is used.
 * Otherwise, if Spring MVC is on the classpath a {@link HandlerMappingIntrospector} is
 * used.
 *
 * @param <H> the builder to return.
 * @author Rob Winch
 * @since 4.1.1
 */
public class CorsConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<CorsConfigurer<H>, H> {

	private static final String HANDLER_MAPPING_INTROSPECTOR = "org.springframework.web.servlet.handler.HandlerMappingIntrospector";

	private static final String CORS_CONFIGURATION_SOURCE_BEAN_NAME = "corsConfigurationSource";

	private static final String CORS_FILTER_BEAN_NAME = "corsFilter";

	private CorsConfigurationSource configurationSource;

	/**
	 * Creates a new instance
	 *
	 * @see HttpSecurity#cors()
	 */
	public CorsConfigurer() {
	}

	public CorsConfigurer<H> configurationSource(CorsConfigurationSource configurationSource) {
		this.configurationSource = configurationSource;
		return this;
	}

	@Override
	public void configure(H http) {
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);

		CorsFilter corsFilter = getCorsFilter(context);
		if (corsFilter == null) {
			throw new IllegalStateException("Please configure either a " + CORS_FILTER_BEAN_NAME + " bean or a "
					+ CORS_CONFIGURATION_SOURCE_BEAN_NAME + "bean.");
		}
		http.addFilter(corsFilter);
	}

	private CorsFilter getCorsFilter(ApplicationContext context) {
		if (this.configurationSource != null) {
			return new CorsFilter(this.configurationSource);
		}

		boolean containsCorsFilter = context.containsBeanDefinition(CORS_FILTER_BEAN_NAME);
		if (containsCorsFilter) {
			return context.getBean(CORS_FILTER_BEAN_NAME, CorsFilter.class);
		}

		boolean containsCorsSource = context.containsBean(CORS_CONFIGURATION_SOURCE_BEAN_NAME);
		if (containsCorsSource) {
			CorsConfigurationSource configurationSource = context.getBean(CORS_CONFIGURATION_SOURCE_BEAN_NAME,
					CorsConfigurationSource.class);
			return new CorsFilter(configurationSource);
		}

		boolean mvcPresent = ClassUtils.isPresent(HANDLER_MAPPING_INTROSPECTOR, context.getClassLoader());
		if (mvcPresent) {
			return MvcCorsFilter.getMvcCorsFilter(context);
		}
		return null;
	}

	static class MvcCorsFilter {

		private static final String HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME = "mvcHandlerMappingIntrospector";

		/**
		 * This needs to be isolated into a separate class as Spring MVC is an optional
		 * dependency and will potentially cause ClassLoading issues
		 * @param context
		 * @return
		 */
		private static CorsFilter getMvcCorsFilter(ApplicationContext context) {
			if (!context.containsBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME)) {
				throw new NoSuchBeanDefinitionException(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME, "A Bean named "
						+ HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME + " of type "
						+ HandlerMappingIntrospector.class.getName()
						+ " is required to use MvcRequestMatcher. Please ensure Spring Security & Spring MVC are configured in a shared ApplicationContext.");
			}
			HandlerMappingIntrospector mappingIntrospector = context.getBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME,
					HandlerMappingIntrospector.class);
			return new CorsFilter(mappingIntrospector);
		}

	}

}
