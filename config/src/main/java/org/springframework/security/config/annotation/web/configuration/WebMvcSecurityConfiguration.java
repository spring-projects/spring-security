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

package org.springframework.security.config.annotation.web.configuration;

import java.io.IOException;
import java.util.List;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.expression.BeanFactoryResolver;
import org.springframework.expression.BeanResolver;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.HandlerMappingIntrospectorRequestTransformer;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.debug.DebugFilter;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.RequestRejectedHandler;
import org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.web.method.annotation.CsrfTokenArgumentResolver;
import org.springframework.security.web.method.annotation.CurrentSecurityContextArgumentResolver;
import org.springframework.security.web.servlet.support.csrf.CsrfRequestDataValueProcessor;
import org.springframework.web.filter.CompositeFilter;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;
import org.springframework.web.servlet.support.RequestDataValueProcessor;

/**
 * Used to add a {@link RequestDataValueProcessor} for Spring MVC and Spring Security CSRF
 * integration. This configuration is added whenever {@link EnableWebMvc} is added by
 * <a href="
 * {@docRoot}/org/springframework/security/config/annotation/web/configuration/SpringWebMvcImportSelector.html">SpringWebMvcImportSelector</a> and
 * the DispatcherServlet is present on the classpath. It also adds the
 * {@link AuthenticationPrincipalArgumentResolver} as a
 * {@link HandlerMethodArgumentResolver}.
 *
 * @author Rob Winch
 * @author Dan Zheng
 * @since 3.2
 */
class WebMvcSecurityConfiguration implements WebMvcConfigurer, ApplicationContextAware {

	private static final String HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME = "mvcHandlerMappingIntrospector";

	private BeanResolver beanResolver;

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	private AnnotationTemplateExpressionDefaults templateDefaults;

	@Override
	@SuppressWarnings("deprecation")
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
		AuthenticationPrincipalArgumentResolver authenticationPrincipalResolver = new AuthenticationPrincipalArgumentResolver();
		authenticationPrincipalResolver.setBeanResolver(this.beanResolver);
		authenticationPrincipalResolver.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
		authenticationPrincipalResolver.setTemplateDefaults(this.templateDefaults);
		argumentResolvers.add(authenticationPrincipalResolver);
		argumentResolvers
			.add(new org.springframework.security.web.bind.support.AuthenticationPrincipalArgumentResolver());
		CurrentSecurityContextArgumentResolver currentSecurityContextArgumentResolver = new CurrentSecurityContextArgumentResolver();
		currentSecurityContextArgumentResolver.setBeanResolver(this.beanResolver);
		currentSecurityContextArgumentResolver.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
		currentSecurityContextArgumentResolver.setTemplateDefaults(this.templateDefaults);
		argumentResolvers.add(currentSecurityContextArgumentResolver);
		argumentResolvers.add(new CsrfTokenArgumentResolver());
	}

	@Bean
	RequestDataValueProcessor requestDataValueProcessor() {
		return new CsrfRequestDataValueProcessor();
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.beanResolver = new BeanFactoryResolver(applicationContext.getAutowireCapableBeanFactory());
		if (applicationContext.getBeanNamesForType(SecurityContextHolderStrategy.class).length == 1) {
			this.securityContextHolderStrategy = applicationContext.getBean(SecurityContextHolderStrategy.class);
		}
		if (applicationContext.getBeanNamesForType(AnnotationTemplateExpressionDefaults.class).length == 1) {
			this.templateDefaults = applicationContext.getBean(AnnotationTemplateExpressionDefaults.class);
		}
	}

	/**
	 * Used to ensure Spring MVC request matching is cached.
	 *
	 * Creates a {@link BeanDefinitionRegistryPostProcessor} that detects if a bean named
	 * HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME is defined. If so, it moves the
	 * AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME to another bean name
	 * and then adds a {@link CompositeFilter} that contains
	 * {@link HandlerMappingIntrospector#createCacheFilter()} and the original
	 * FilterChainProxy under the original Bean name.
	 * @return
	 */
	@Bean
	static BeanDefinitionRegistryPostProcessor springSecurityHandlerMappingIntrospectorBeanDefinitionRegistryPostProcessor() {
		return new BeanDefinitionRegistryPostProcessor() {
			@Override
			public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
			}

			@Override
			public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
				if (!registry.containsBeanDefinition(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME)) {
					return;
				}

				String hmiRequestTransformerBeanName = HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME + "RequestTransformer";
				if (!registry.containsBeanDefinition(hmiRequestTransformerBeanName)) {
					BeanDefinition hmiRequestTransformer = BeanDefinitionBuilder
						.rootBeanDefinition(HandlerMappingIntrospectorRequestTransformer.class)
						.addConstructorArgReference(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME)
						.getBeanDefinition();
					registry.registerBeanDefinition(hmiRequestTransformerBeanName, hmiRequestTransformer);
				}

				BeanDefinition filterChainProxy = registry
					.getBeanDefinition(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME);

				if (!filterChainProxy.getResolvableType().isInstance(CompositeFilterChainProxy.class)) {
					BeanDefinitionBuilder hmiCacheFilterBldr = BeanDefinitionBuilder
						.rootBeanDefinition(HandlerMappingIntrospectorCacheFilterFactoryBean.class)
						.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);

					ManagedList<BeanMetadataElement> filters = new ManagedList<>();
					filters.add(hmiCacheFilterBldr.getBeanDefinition());
					filters.add(filterChainProxy);
					BeanDefinitionBuilder compositeSpringSecurityFilterChainBldr = BeanDefinitionBuilder
						.rootBeanDefinition(CompositeFilterChainProxy.class)
						.addConstructorArgValue(filters);

					registry.removeBeanDefinition(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME);
					registry.registerBeanDefinition(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME,
							compositeSpringSecurityFilterChainBldr.getBeanDefinition());
				}
			}
		};
	}

	/**
	 * {@link FactoryBean} to defer creation of
	 * {@link HandlerMappingIntrospector#createCacheFilter()}
	 */
	static class HandlerMappingIntrospectorCacheFilterFactoryBean
			implements ApplicationContextAware, FactoryBean<Filter> {

		private ApplicationContext applicationContext;

		@Override
		public void setApplicationContext(ApplicationContext applicationContext) {
			this.applicationContext = applicationContext;
		}

		@Override
		public Filter getObject() throws Exception {
			HandlerMappingIntrospector handlerMappingIntrospector = this.applicationContext
				.getBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME, HandlerMappingIntrospector.class);
			return handlerMappingIntrospector.createCacheFilter();
		}

		@Override
		public Class<?> getObjectType() {
			return Filter.class;
		}

	}

	/**
	 * Extends {@link FilterChainProxy} to provide as much passivity as possible but
	 * delegates to {@link CompositeFilter} for
	 * {@link #doFilter(ServletRequest, ServletResponse, FilterChain)}.
	 */
	static class CompositeFilterChainProxy extends FilterChainProxy {

		/**
		 * Used for {@link #doFilter(ServletRequest, ServletResponse, FilterChain)}
		 */
		private final Filter doFilterDelegate;

		private final FilterChainProxy springSecurityFilterChain;

		/**
		 * Creates a new instance
		 * @param filters the Filters to delegate to. One of which must be
		 * FilterChainProxy.
		 */
		CompositeFilterChainProxy(List<? extends Filter> filters) {
			this.doFilterDelegate = createDoFilterDelegate(filters);
			this.springSecurityFilterChain = findFilterChainProxy(filters);
		}

		@Override
		public void afterPropertiesSet() {
			this.springSecurityFilterChain.afterPropertiesSet();
		}

		@Override
		public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
				throws IOException, ServletException {
			this.doFilterDelegate.doFilter(request, response, chain);
		}

		@Override
		public List<Filter> getFilters(String url) {
			return this.springSecurityFilterChain.getFilters(url);
		}

		@Override
		public List<SecurityFilterChain> getFilterChains() {
			return this.springSecurityFilterChain.getFilterChains();
		}

		@Override
		public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
			this.springSecurityFilterChain.setSecurityContextHolderStrategy(securityContextHolderStrategy);
		}

		@Override
		public void setFilterChainValidator(FilterChainValidator filterChainValidator) {
			this.springSecurityFilterChain.setFilterChainValidator(filterChainValidator);
		}

		@Override
		public void setFilterChainDecorator(FilterChainDecorator filterChainDecorator) {
			this.springSecurityFilterChain.setFilterChainDecorator(filterChainDecorator);
		}

		@Override
		public void setFirewall(HttpFirewall firewall) {
			this.springSecurityFilterChain.setFirewall(firewall);
		}

		@Override
		public void setRequestRejectedHandler(RequestRejectedHandler requestRejectedHandler) {
			this.springSecurityFilterChain.setRequestRejectedHandler(requestRejectedHandler);
		}

		/**
		 * Used through reflection by Spring Security's Test support to lookup the
		 * FilterChainProxy Filters for a specific HttpServletRequest.
		 * @param request
		 * @return
		 */
		private List<? extends Filter> getFilters(HttpServletRequest request) {
			List<SecurityFilterChain> filterChains = this.springSecurityFilterChain.getFilterChains();
			for (SecurityFilterChain chain : filterChains) {
				if (chain.matches(request)) {
					return chain.getFilters();
				}
			}
			return null;
		}

		/**
		 * Creates the Filter to delegate to for doFilter
		 * @param filters the Filters to delegate to.
		 * @return the Filter for doFilter
		 */
		private static Filter createDoFilterDelegate(List<? extends Filter> filters) {
			CompositeFilter delegate = new CompositeFilter();
			delegate.setFilters(filters);
			return delegate;
		}

		/**
		 * Find the FilterChainProxy in a List of Filter
		 * @param filters
		 * @return non-null FilterChainProxy
		 * @throws IllegalStateException if the FilterChainProxy cannot be found
		 */
		private static FilterChainProxy findFilterChainProxy(List<? extends Filter> filters) {
			for (Filter filter : filters) {
				if (filter instanceof FilterChainProxy fcp) {
					return fcp;
				}
				if (filter instanceof DebugFilter debugFilter) {
					return debugFilter.getFilterChainProxy();
				}
			}
			throw new IllegalStateException("Couldn't find FilterChainProxy in " + filters);
		}

	}

}
