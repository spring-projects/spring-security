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

package org.springframework.security.config.annotation.web.configurers;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.PreFlightRequestHandler;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.filter.PreFlightRequestFilter;

/**
 * Adds {@link CorsFilter} or {@link PreFlightRequestFilter} to the Spring Security filter
 * chain. If a bean by the name of corsFilter is provided, that {@link CorsFilter} is
 * used. Else if corsConfigurationSource is defined, then that
 * {@link CorsConfigurationSource} is used. If a {@link PreFlightRequestHandler} is set on
 * this configurer, {@link CorsFilter} is not used and {@link PreFlightRequestFilter} is
 * registered instead.
 *
 * @param <H> the builder to return.
 * @author Rob Winch
 * @since 4.1.1
 */
public class CorsConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<CorsConfigurer<H>, H> {

	private static final String CORS_CONFIGURATION_SOURCE_BEAN_NAME = "corsConfigurationSource";

	private static final String CORS_FILTER_BEAN_NAME = "corsFilter";

	private CorsConfigurationSource configurationSource;

	private PreFlightRequestHandler preFlightRequestHandler;

	/**
	 * Creates a new instance
	 *
	 * @see HttpSecurity#cors(Customizer)
	 */
	public CorsConfigurer() {
	}

	public CorsConfigurer<H> configurationSource(CorsConfigurationSource configurationSource) {
		this.configurationSource = configurationSource;
		return this;
	}

	/**
	 * Use the given {@link PreFlightRequestHandler} for CORS preflight requests. When
	 * set, {@link CorsFilter} is not used. Cannot be combined with
	 * {@link #configurationSource(CorsConfigurationSource)}.
	 * @param preFlightRequestHandler the handler to use
	 * @return the {@link CorsConfigurer} for additional configuration
	 */
	public CorsConfigurer<H> preFlightRequestHandler(PreFlightRequestHandler preFlightRequestHandler) {
		this.preFlightRequestHandler = preFlightRequestHandler;
		return this;
	}

	@Override
	public void configure(H http) {
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);

		if (this.configurationSource != null && this.preFlightRequestHandler != null) {
			throw new IllegalStateException(
					"Cannot configure both a CorsConfigurationSource and a PreFlightRequestHandler on CorsConfigurer");
		}

		CorsFilter corsFilter = getCorsFilter(context);
		if (corsFilter != null) {
			http.addFilter(corsFilter);
			return;
		}
		PreFlightRequestHandler preFlightRequestHandlerBean = getPreFlightRequestHandler(context);
		if (preFlightRequestHandlerBean != null) {
			http.addFilterBefore(new PreFlightRequestFilter(preFlightRequestHandlerBean), CorsFilter.class);
			return;
		}
		throw new NoSuchBeanDefinitionException(CorsConfigurationSource.class,
				"Failed to find a bean that implements `CorsConfigurationSource`. Please ensure that you are using "
						+ "`@EnableWebMvc`, are publishing a `WebMvcConfigurer`, or are publishing a `CorsConfigurationSource` bean.");
	}

	private PreFlightRequestHandler getPreFlightRequestHandler(ApplicationContext context) {
		if (this.configurationSource != null) {
			return null;
		}
		if (this.preFlightRequestHandler != null) {
			return this.preFlightRequestHandler;
		}
		if (context == null) {
			return null;
		}
		if (context.getBeanNamesForType(PreFlightRequestHandler.class).length > 0) {
			return context.getBean(PreFlightRequestHandler.class);
		}
		return null;
	}

	private CorsConfigurationSource getCorsConfigurationSource(ApplicationContext context) {
		if (context == null) {
			return null;
		}
		boolean containsCorsSource = context.containsBeanDefinition(CORS_CONFIGURATION_SOURCE_BEAN_NAME);
		if (containsCorsSource) {
			return context.getBean(CORS_CONFIGURATION_SOURCE_BEAN_NAME, CorsConfigurationSource.class);
		}
		return MvcCorsFilter.getMvcCorsConfigurationSource(context);
	}

	private CorsFilter getCorsFilter(ApplicationContext context) {
		if (this.preFlightRequestHandler != null) {
			return null;
		}
		if (this.configurationSource != null) {
			return new CorsFilter(this.configurationSource);
		}
		boolean containsCorsFilter = context != null && context.containsBeanDefinition(CORS_FILTER_BEAN_NAME);
		if (containsCorsFilter) {
			return context.getBean(CORS_FILTER_BEAN_NAME, CorsFilter.class);
		}
		CorsConfigurationSource corsConfigurationSource = getCorsConfigurationSource(context);
		if (corsConfigurationSource != null) {
			return new CorsFilter(corsConfigurationSource);
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
		private static CorsConfigurationSource getMvcCorsConfigurationSource(ApplicationContext context) {
			if (context.containsBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME)) {
				return context.getBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME, CorsConfigurationSource.class);
			}
			return null;
		}

	}

}
