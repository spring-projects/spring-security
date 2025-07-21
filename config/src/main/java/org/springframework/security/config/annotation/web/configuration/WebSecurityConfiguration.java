/*
 * Copyright 2002-2025 the original author or authors.
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
import java.util.Collections;
import java.util.List;
import java.util.Map;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.ImportAware;
import org.springframework.core.OrderComparator;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.annotation.Order;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.crypto.RsaKeyConversionServicePostProcessor;
import org.springframework.security.context.DelegatingApplicationListener;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.debug.DebugFilter;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.RequestRejectedHandler;
import org.springframework.web.filter.CompositeFilter;
import org.springframework.web.filter.ServletRequestPathFilter;

/**
 * Uses a {@link WebSecurity} to create the {@link FilterChainProxy} that performs the web
 * based security for Spring Security. It then exports the necessary beans. Customizations
 * can be made to {@link WebSecurity} by implementing {@link WebSecurityConfigurer} and
 * exposing it as a {@link Configuration} or exposing a {@link WebSecurityCustomizer}
 * bean. This configuration is imported when using {@link EnableWebSecurity}.
 *
 * @author Rob Winch
 * @author Keesun Baik
 * @since 3.2
 * @see EnableWebSecurity
 * @see WebSecurity
 */
@Configuration(proxyBeanMethods = false)
public class WebSecurityConfiguration implements ImportAware {

	private WebSecurity webSecurity;

	private Boolean debugEnabled;

	private List<SecurityFilterChain> securityFilterChains = Collections.emptyList();

	private List<WebSecurityCustomizer> webSecurityCustomizers = Collections.emptyList();

	@Bean
	public static DelegatingApplicationListener delegatingApplicationListener() {
		return new DelegatingApplicationListener();
	}

	@Bean
	@DependsOn(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public SecurityExpressionHandler<FilterInvocation> webSecurityExpressionHandler() {
		return this.webSecurity.getExpressionHandler();
	}

	/**
	 * Creates the Spring Security Filter Chain
	 * @return the {@link Filter} that represents the security filter chain
	 * @throws Exception
	 */
	@Bean(name = AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public Filter springSecurityFilterChain(ObjectProvider<HttpSecurity> provider) throws Exception {
		boolean hasFilterChain = !this.securityFilterChains.isEmpty();
		if (!hasFilterChain) {
			this.webSecurity.addSecurityFilterChainBuilder(() -> {
				HttpSecurity httpSecurity = provider.getObject();
				httpSecurity.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated());
				httpSecurity.formLogin(Customizer.withDefaults());
				httpSecurity.httpBasic(Customizer.withDefaults());
				return httpSecurity.build();
			});
		}
		for (SecurityFilterChain securityFilterChain : this.securityFilterChains) {
			this.webSecurity.addSecurityFilterChainBuilder(() -> securityFilterChain);
		}
		for (WebSecurityCustomizer customizer : this.webSecurityCustomizers) {
			customizer.customize(this.webSecurity);
		}
		return this.webSecurity.build();
	}

	/**
	 * Creates the {@link WebInvocationPrivilegeEvaluator} that is necessary to evaluate
	 * privileges for a given web URI
	 * @return the {@link WebInvocationPrivilegeEvaluator}
	 */
	@Bean
	@DependsOn(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME)
	public WebInvocationPrivilegeEvaluator privilegeEvaluator() {
		return this.webSecurity.getPrivilegeEvaluator();
	}

	/**
	 * Sets the {@code <SecurityConfigurer<FilterChainProxy, WebSecurityBuilder>}
	 * instances used to create the web configuration.
	 * @param objectPostProcessor the {@link ObjectPostProcessor} used to create a
	 * {@link WebSecurity} instance
	 * @param beanFactory the bean factory to use to retrieve the relevant
	 * {@code <SecurityConfigurer<FilterChainProxy, WebSecurityBuilder>} instances used to
	 * create the web configuration
	 * @throws Exception
	 */
	@Autowired(required = false)
	public void setFilterChainProxySecurityConfigurer(ObjectPostProcessor<Object> objectPostProcessor,
			ConfigurableListableBeanFactory beanFactory) throws Exception {
		this.webSecurity = objectPostProcessor.postProcess(new WebSecurity(objectPostProcessor));
		if (this.debugEnabled != null) {
			this.webSecurity.debug(this.debugEnabled);
		}
		List<SecurityConfigurer<Filter, WebSecurity>> webSecurityConfigurers = new AutowiredWebSecurityConfigurersIgnoreParents(
				beanFactory)
			.getWebSecurityConfigurers();
		webSecurityConfigurers.sort(AnnotationAwareOrderComparator.INSTANCE);
		Integer previousOrder = null;
		Object previousConfig = null;
		for (SecurityConfigurer<Filter, WebSecurity> config : webSecurityConfigurers) {
			Integer order = AnnotationAwareOrderComparator.lookupOrder(config);
			if (previousOrder != null && previousOrder.equals(order)) {
				throw new IllegalStateException("@Order on WebSecurityConfigurers must be unique. Order of " + order
						+ " was already used on " + previousConfig + ", so it cannot be used on " + config + " too.");
			}
			previousOrder = order;
			previousConfig = config;
		}
		for (SecurityConfigurer<Filter, WebSecurity> webSecurityConfigurer : webSecurityConfigurers) {
			this.webSecurity.apply(webSecurityConfigurer);
		}
	}

	@Autowired(required = false)
	void setFilterChains(List<SecurityFilterChain> securityFilterChains) {
		this.securityFilterChains = securityFilterChains;
	}

	@Autowired(required = false)
	void setWebSecurityCustomizers(List<WebSecurityCustomizer> webSecurityCustomizers) {
		this.webSecurityCustomizers = webSecurityCustomizers;
	}

	@Bean
	public static BeanFactoryPostProcessor conversionServicePostProcessor() {
		return new RsaKeyConversionServicePostProcessor();
	}

	@Override
	public void setImportMetadata(AnnotationMetadata importMetadata) {
		Map<String, Object> enableWebSecurityAttrMap = importMetadata
			.getAnnotationAttributes(EnableWebSecurity.class.getName());
		AnnotationAttributes enableWebSecurityAttrs = AnnotationAttributes.fromMap(enableWebSecurityAttrMap);
		this.debugEnabled = enableWebSecurityAttrs.getBoolean("debug");
		if (this.webSecurity != null) {
			this.webSecurity.debug(this.debugEnabled);
		}
	}

	/**
	 * Used to ensure Spring MVC request matching is cached.
	 *
	 * Creates a {@link BeanDefinitionRegistryPostProcessor} that moves the
	 * AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME to another bean name
	 * and then adds a {@link CompositeFilter} that contains
	 * {@link ServletRequestPathFilter} and the original FilterChainProxy under the
	 * original Bean name.
	 * @return
	 */
	@Bean
	static BeanDefinitionRegistryPostProcessor springSecurityPathPatternParserBeanDefinitionRegistryPostProcessor() {
		return new BeanDefinitionRegistryPostProcessor() {
			@Override
			public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
			}

			@Override
			public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry registry) throws BeansException {
				BeanDefinition filterChainProxy = registry
					.getBeanDefinition(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME);

				if (filterChainProxy.getResolvableType().isInstance(CompositeFilterChainProxy.class)) {
					return;
				}

				BeanDefinitionBuilder pppCacheFilterBldr = BeanDefinitionBuilder
					.rootBeanDefinition(ServletRequestPathFilter.class)
					.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);

				ManagedList<BeanMetadataElement> filters = new ManagedList<>();
				filters.add(pppCacheFilterBldr.getBeanDefinition());
				filters.add(filterChainProxy);
				BeanDefinitionBuilder compositeSpringSecurityFilterChainBldr = BeanDefinitionBuilder
					.rootBeanDefinition(CompositeFilterChainProxy.class)
					.addConstructorArgValue(filters);

				registry.removeBeanDefinition(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME);
				registry.registerBeanDefinition(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME,
						compositeSpringSecurityFilterChainBldr.getBeanDefinition());
			}
		};
	}

	/**
	 * A custom version of the Spring provided AnnotationAwareOrderComparator that uses
	 * {@link AnnotationUtils#findAnnotation(Class, Class)} to look on super class
	 * instances for the {@link Order} annotation.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	private static class AnnotationAwareOrderComparator extends OrderComparator {

		private static final AnnotationAwareOrderComparator INSTANCE = new AnnotationAwareOrderComparator();

		@Override
		protected int getOrder(Object obj) {
			return lookupOrder(obj);
		}

		private static int lookupOrder(Object obj) {
			if (obj instanceof Ordered) {
				return ((Ordered) obj).getOrder();
			}
			if (obj != null) {
				Class<?> clazz = ((obj instanceof Class) ? (Class<?>) obj : obj.getClass());
				Order order = AnnotationUtils.findAnnotation(clazz, Order.class);
				if (order != null) {
					return order.value();
				}
			}
			return Ordered.LOWEST_PRECEDENCE;
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
