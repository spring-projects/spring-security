/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web.builders;

import java.util.ArrayList;
import java.util.List;

import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.Filter;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.ObservationFilterChainDecorator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AuthorizationManagerWebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.RequestMatcherDelegatingWebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.debug.DebugFilter;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.ObservationMarkingRequestRejectedHandler;
import org.springframework.security.web.firewall.RequestRejectedHandler;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.util.Assert;
import org.springframework.web.context.ServletContextAware;
import org.springframework.web.filter.DelegatingFilterProxy;

/**
 * <p>
 * The {@link WebSecurity} is created by {@link WebSecurityConfiguration} to create the
 * {@link FilterChainProxy} known as the Spring Security Filter Chain
 * (springSecurityFilterChain). The springSecurityFilterChain is the {@link Filter} that
 * the {@link DelegatingFilterProxy} delegates to.
 * </p>
 *
 * <p>
 * Customizations to the {@link WebSecurity} can be made by creating a
 * {@link WebSecurityConfigurer} or exposing a {@link WebSecurityCustomizer} bean.
 * </p>
 *
 * @author Rob Winch
 * @author Evgeniy Cheban
 * @since 3.2
 * @see EnableWebSecurity
 * @see WebSecurityConfiguration
 */
public final class WebSecurity extends AbstractConfiguredSecurityBuilder<Filter, WebSecurity>
		implements SecurityBuilder<Filter>, ApplicationContextAware, ServletContextAware {

	private final Log logger = LogFactory.getLog(getClass());

	private final List<RequestMatcher> ignoredRequests = new ArrayList<>();

	private final List<SecurityBuilder<? extends SecurityFilterChain>> securityFilterChainBuilders = new ArrayList<>();

	private IgnoredRequestConfigurer ignoredRequestRegistry;

	private HttpFirewall httpFirewall;

	private RequestRejectedHandler requestRejectedHandler;

	private boolean debugEnabled;

	private WebInvocationPrivilegeEvaluator privilegeEvaluator;

	private ObservationRegistry observationRegistry = ObservationRegistry.NOOP;

	private DefaultWebSecurityExpressionHandler defaultWebSecurityExpressionHandler = new DefaultWebSecurityExpressionHandler();

	private SecurityExpressionHandler<FilterInvocation> expressionHandler = this.defaultWebSecurityExpressionHandler;

	private Runnable postBuildAction = () -> {
	};

	private ServletContext servletContext;

	/**
	 * Creates a new instance
	 * @param objectPostProcessor the {@link ObjectPostProcessor} to use
	 * @see WebSecurityConfiguration
	 */
	public WebSecurity(ObjectPostProcessor<Object> objectPostProcessor) {
		super(objectPostProcessor);
	}

	/**
	 * <p>
	 * Allows adding {@link RequestMatcher} instances that Spring Security should ignore.
	 * Web Security provided by Spring Security (including the {@link SecurityContext})
	 * will not be available on {@link HttpServletRequest} that match. Typically the
	 * requests that are registered should be that of only static resources. For requests
	 * that are dynamic, consider mapping the request to allow all users instead.
	 * </p>
	 *
	 * Example Usage:
	 *
	 * <pre>
	 * webSecurityBuilder.ignoring()
	 * // ignore all URLs that start with /resources/ or /static/
	 * 		.requestMatchers(&quot;/resources/**&quot;, &quot;/static/**&quot;);
	 * </pre>
	 *
	 * Alternatively this will accomplish the same result:
	 *
	 * <pre>
	 * webSecurityBuilder.ignoring()
	 * // ignore all URLs that start with /resources/ or /static/
	 * 		.requestMatchers(&quot;/resources/**&quot;).requestMatchers(&quot;/static/**&quot;);
	 * </pre>
	 *
	 * Multiple invocations of ignoring() are also additive, so the following is also
	 * equivalent to the previous two examples:
	 *
	 * <pre>
	 * webSecurityBuilder.ignoring()
	 * // ignore all URLs that start with /resources/
	 * 		.requestMatchers(&quot;/resources/**&quot;);
	 * webSecurityBuilder.ignoring()
	 * // ignore all URLs that start with /static/
	 * 		.requestMatchers(&quot;/static/**&quot;);
	 * // now both URLs that start with /resources/ and /static/ will be ignored
	 * </pre>
	 * @return the {@link IgnoredRequestConfigurer} to use for registering request that
	 * should be ignored
	 */
	public IgnoredRequestConfigurer ignoring() {
		return this.ignoredRequestRegistry;
	}

	/**
	 * Allows customizing the {@link HttpFirewall}. The default is
	 * {@link StrictHttpFirewall}.
	 * @param httpFirewall the custom {@link HttpFirewall}
	 * @return the {@link WebSecurity} for further customizations
	 */
	public WebSecurity httpFirewall(HttpFirewall httpFirewall) {
		this.httpFirewall = httpFirewall;
		return this;
	}

	/**
	 * Controls debugging support for Spring Security.
	 * @param debugEnabled if true, enables debug support with Spring Security. Default is
	 * false.
	 * @return the {@link WebSecurity} for further customization.
	 * @see EnableWebSecurity#debug()
	 */
	public WebSecurity debug(boolean debugEnabled) {
		this.debugEnabled = debugEnabled;
		return this;
	}

	/**
	 * <p>
	 * Adds builders to create {@link SecurityFilterChain} instances.
	 * </p>
	 *
	 * <p>
	 * Typically this method is invoked automatically within the framework from
	 * {@link WebSecurityConfiguration#springSecurityFilterChain()}
	 * </p>
	 * @param securityFilterChainBuilder the builder to use to create the
	 * {@link SecurityFilterChain} instances
	 * @return the {@link WebSecurity} for further customizations
	 */
	public WebSecurity addSecurityFilterChainBuilder(
			SecurityBuilder<? extends SecurityFilterChain> securityFilterChainBuilder) {
		this.securityFilterChainBuilders.add(securityFilterChainBuilder);
		return this;
	}

	/**
	 * Set the {@link WebInvocationPrivilegeEvaluator} to be used. If this is not
	 * specified, then a {@link RequestMatcherDelegatingWebInvocationPrivilegeEvaluator}
	 * will be created based on the list of {@link SecurityFilterChain}.
	 * @param privilegeEvaluator the {@link WebInvocationPrivilegeEvaluator} to use
	 * @return the {@link WebSecurity} for further customizations
	 */
	public WebSecurity privilegeEvaluator(WebInvocationPrivilegeEvaluator privilegeEvaluator) {
		this.privilegeEvaluator = privilegeEvaluator;
		return this;
	}

	/**
	 * Set the {@link SecurityExpressionHandler} to be used. If this is not specified,
	 * then a {@link DefaultWebSecurityExpressionHandler} will be used.
	 * @param expressionHandler the {@link SecurityExpressionHandler} to use
	 * @return the {@link WebSecurity} for further customizations
	 */
	public WebSecurity expressionHandler(SecurityExpressionHandler<FilterInvocation> expressionHandler) {
		Assert.notNull(expressionHandler, "expressionHandler cannot be null");
		this.expressionHandler = expressionHandler;
		return this;
	}

	/**
	 * Gets the {@link SecurityExpressionHandler} to be used.
	 * @return the {@link SecurityExpressionHandler} for further customizations
	 */
	public SecurityExpressionHandler<FilterInvocation> getExpressionHandler() {
		return this.expressionHandler;
	}

	/**
	 * Gets the {@link WebInvocationPrivilegeEvaluator} to be used.
	 * @return the {@link WebInvocationPrivilegeEvaluator} for further customizations
	 */
	public WebInvocationPrivilegeEvaluator getPrivilegeEvaluator() {
		return this.privilegeEvaluator;
	}

	/**
	 * Executes the Runnable immediately after the build takes place
	 * @param postBuildAction
	 * @return the {@link WebSecurity} for further customizations
	 */
	public WebSecurity postBuildAction(Runnable postBuildAction) {
		this.postBuildAction = postBuildAction;
		return this;
	}

	/**
	 * Sets the handler to handle
	 * {@link org.springframework.security.web.firewall.RequestRejectedException}
	 * @param requestRejectedHandler
	 * @return the {@link WebSecurity} for further customizations
	 * @since 5.7
	 */
	public WebSecurity requestRejectedHandler(RequestRejectedHandler requestRejectedHandler) {
		Assert.notNull(requestRejectedHandler, "requestRejectedHandler cannot be null");
		this.requestRejectedHandler = requestRejectedHandler;
		return this;
	}

	@Override
	protected Filter performBuild() throws Exception {
		Assert.state(!this.securityFilterChainBuilders.isEmpty(),
				() -> "At least one SecurityBuilder<? extends SecurityFilterChain> needs to be specified. "
						+ "Typically this is done by exposing a SecurityFilterChain bean. "
						+ "More advanced users can invoke " + WebSecurity.class.getSimpleName()
						+ ".addSecurityFilterChainBuilder directly");
		int chainSize = this.ignoredRequests.size() + this.securityFilterChainBuilders.size();
		List<SecurityFilterChain> securityFilterChains = new ArrayList<>(chainSize);
		List<RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>>> requestMatcherPrivilegeEvaluatorsEntries = new ArrayList<>();
		for (RequestMatcher ignoredRequest : this.ignoredRequests) {
			WebSecurity.this.logger.warn("You are asking Spring Security to ignore " + ignoredRequest
					+ ". This is not recommended -- please use permitAll via HttpSecurity#authorizeHttpRequests instead.");
			SecurityFilterChain securityFilterChain = new DefaultSecurityFilterChain(ignoredRequest);
			securityFilterChains.add(securityFilterChain);
			requestMatcherPrivilegeEvaluatorsEntries
					.add(getRequestMatcherPrivilegeEvaluatorsEntry(securityFilterChain));
		}
		for (SecurityBuilder<? extends SecurityFilterChain> securityFilterChainBuilder : this.securityFilterChainBuilders) {
			SecurityFilterChain securityFilterChain = securityFilterChainBuilder.build();
			securityFilterChains.add(securityFilterChain);
			requestMatcherPrivilegeEvaluatorsEntries
					.add(getRequestMatcherPrivilegeEvaluatorsEntry(securityFilterChain));
		}
		if (this.privilegeEvaluator == null) {
			this.privilegeEvaluator = new RequestMatcherDelegatingWebInvocationPrivilegeEvaluator(
					requestMatcherPrivilegeEvaluatorsEntries);
		}
		FilterChainProxy filterChainProxy = new FilterChainProxy(securityFilterChains);
		if (this.httpFirewall != null) {
			filterChainProxy.setFirewall(this.httpFirewall);
		}
		if (this.requestRejectedHandler != null) {
			filterChainProxy.setRequestRejectedHandler(this.requestRejectedHandler);
		}
		else if (!this.observationRegistry.isNoop()) {
			filterChainProxy
					.setRequestRejectedHandler(new ObservationMarkingRequestRejectedHandler(this.observationRegistry));
		}
		filterChainProxy.setFilterChainDecorator(getFilterChainDecorator());
		filterChainProxy.afterPropertiesSet();

		Filter result = filterChainProxy;
		if (this.debugEnabled) {
			this.logger.warn("\n\n" + "********************************************************************\n"
					+ "**********        Security debugging is enabled.       *************\n"
					+ "**********    This may include sensitive information.  *************\n"
					+ "**********      Do not use in a production system!     *************\n"
					+ "********************************************************************\n\n");
			result = new DebugFilter(filterChainProxy);
		}

		this.postBuildAction.run();
		return result;
	}

	private RequestMatcherEntry<List<WebInvocationPrivilegeEvaluator>> getRequestMatcherPrivilegeEvaluatorsEntry(
			SecurityFilterChain securityFilterChain) {
		List<WebInvocationPrivilegeEvaluator> privilegeEvaluators = new ArrayList<>();
		for (Filter filter : securityFilterChain.getFilters()) {
			if (filter instanceof FilterSecurityInterceptor) {
				DefaultWebInvocationPrivilegeEvaluator defaultWebInvocationPrivilegeEvaluator = new DefaultWebInvocationPrivilegeEvaluator(
						(FilterSecurityInterceptor) filter);
				defaultWebInvocationPrivilegeEvaluator.setServletContext(this.servletContext);
				privilegeEvaluators.add(defaultWebInvocationPrivilegeEvaluator);
				continue;
			}
			if (filter instanceof AuthorizationFilter) {
				AuthorizationManager<HttpServletRequest> authorizationManager = ((AuthorizationFilter) filter)
						.getAuthorizationManager();
				AuthorizationManagerWebInvocationPrivilegeEvaluator evaluator = new AuthorizationManagerWebInvocationPrivilegeEvaluator(
						authorizationManager);
				evaluator.setServletContext(this.servletContext);
				privilegeEvaluators.add(evaluator);
			}
		}
		return new RequestMatcherEntry<>(securityFilterChain::matches, privilegeEvaluators);
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.defaultWebSecurityExpressionHandler.setApplicationContext(applicationContext);
		try {
			this.defaultWebSecurityExpressionHandler.setRoleHierarchy(applicationContext.getBean(RoleHierarchy.class));
		}
		catch (NoSuchBeanDefinitionException ex) {
		}
		try {
			this.defaultWebSecurityExpressionHandler
					.setPermissionEvaluator(applicationContext.getBean(PermissionEvaluator.class));
		}
		catch (NoSuchBeanDefinitionException ex) {
		}
		this.ignoredRequestRegistry = new IgnoredRequestConfigurer(applicationContext);
		try {
			this.httpFirewall = applicationContext.getBean(HttpFirewall.class);
		}
		catch (NoSuchBeanDefinitionException ex) {
		}
		try {
			this.requestRejectedHandler = applicationContext.getBean(RequestRejectedHandler.class);
		}
		catch (NoSuchBeanDefinitionException ex) {
		}
		try {
			this.observationRegistry = applicationContext.getBean(ObservationRegistry.class);
		}
		catch (NoSuchBeanDefinitionException ex) {
		}
	}

	@Override
	public void setServletContext(ServletContext servletContext) {
		this.servletContext = servletContext;
	}

	FilterChainProxy.FilterChainDecorator getFilterChainDecorator() {
		if (this.observationRegistry.isNoop()) {
			return new FilterChainProxy.VirtualFilterChainDecorator();
		}
		return new ObservationFilterChainDecorator(this.observationRegistry);
	}

	/**
	 * Allows registering {@link RequestMatcher} instances that should be ignored by
	 * Spring Security.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	public class IgnoredRequestConfigurer extends AbstractRequestMatcherRegistry<IgnoredRequestConfigurer> {

		IgnoredRequestConfigurer(ApplicationContext context) {
			setApplicationContext(context);
		}

		@Override
		protected IgnoredRequestConfigurer chainRequestMatchers(List<RequestMatcher> requestMatchers) {
			WebSecurity.this.ignoredRequests.addAll(requestMatchers);
			return this;
		}

		/**
		 * Returns the {@link WebSecurity} to be returned for chaining.
		 */
		public WebSecurity and() {
			return WebSecurity.this;
		}

	}

}
