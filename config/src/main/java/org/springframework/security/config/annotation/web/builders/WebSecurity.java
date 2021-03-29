/*
 * Copyright 2002-2021 the original author or authors.
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
import java.util.Arrays;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.config.annotation.AbstractConfiguredSecurityBuilder;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.debug.DebugFilter;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.RequestRejectedHandler;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.server.restriction.IgnoreRequestMatcher;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
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
 * {@link WebSecurityConfigurer}, overriding {@link WebSecurityConfigurerAdapter} or
 * exposing a {@link WebSecurityCustomizer} bean.
 * </p>
 *
 * @author Rob Winch
 * @author Evgeniy Cheban
 * @since 3.2
 * @see EnableWebSecurity
 * @see WebSecurityConfiguration
 */
public final class WebSecurity extends AbstractConfiguredSecurityBuilder<Filter, WebSecurity>
		implements SecurityBuilder<Filter>, ApplicationContextAware {

	private final Log logger = LogFactory.getLog(getClass());

	private final List<RequestMatcher> ignoredRequests = new ArrayList<>();

	private final List<SecurityBuilder<? extends SecurityFilterChain>> securityFilterChainBuilders = new ArrayList<>();

	private IgnoredRequestConfigurer ignoredRequestRegistry;

	private FilterSecurityInterceptor filterSecurityInterceptor;

	private HttpFirewall httpFirewall;

	private RequestRejectedHandler requestRejectedHandler;

	private boolean debugEnabled;

	private WebInvocationPrivilegeEvaluator privilegeEvaluator;

	private final DefaultWebSecurityExpressionHandler defaultWebSecurityExpressionHandler = new DefaultWebSecurityExpressionHandler();

	private SecurityExpressionHandler<FilterInvocation> expressionHandler = this.defaultWebSecurityExpressionHandler;

	private Runnable postBuildAction = () -> {
	};

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
	 * 		.antMatchers(&quot;/resources/**&quot;, &quot;/static/**&quot;);
	 * </pre>
	 *
	 * Alternatively this will accomplish the same result:
	 *
	 * <pre>
	 * webSecurityBuilder.ignoring()
	 * // ignore all URLs that start with /resources/ or /static/
	 * 		.antMatchers(&quot;/resources/**&quot;).antMatchers(&quot;/static/**&quot;);
	 * </pre>
	 *
	 * Multiple invocations of ignoring() are also additive, so the following is also
	 * equivalent to the previous two examples:
	 *
	 * <pre>
	 * webSecurityBuilder.ignoring()
	 * // ignore all URLs that start with /resources/
	 * 		.antMatchers(&quot;/resources/**&quot;);
	 * webSecurityBuilder.ignoring()
	 * // ignore all URLs that start with /static/
	 * 		.antMatchers(&quot;/static/**&quot;);
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
	 * {@link WebSecurityConfigurerAdapter#init(WebSecurity)}
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
	 * specified, then a {@link DefaultWebInvocationPrivilegeEvaluator} will be created
	 * when {@link #securityInterceptor(FilterSecurityInterceptor)} is non null.
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
		if (this.privilegeEvaluator != null) {
			return this.privilegeEvaluator;
		}
		return (this.filterSecurityInterceptor != null)
				? new DefaultWebInvocationPrivilegeEvaluator(this.filterSecurityInterceptor) : null;
	}

	/**
	 * Sets the {@link FilterSecurityInterceptor}. This is typically invoked by
	 * {@link WebSecurityConfigurerAdapter}.
	 * @param securityInterceptor the {@link FilterSecurityInterceptor} to use
	 * @return the {@link WebSecurity} for further customizations
	 */
	public WebSecurity securityInterceptor(FilterSecurityInterceptor securityInterceptor) {
		this.filterSecurityInterceptor = securityInterceptor;
		return this;
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

	@Override
	protected Filter performBuild() throws Exception {
		Assert.state(!this.securityFilterChainBuilders.isEmpty(),
				() -> "At least one SecurityBuilder<? extends SecurityFilterChain> needs to be specified. "
						+ "Typically this is done by exposing a SecurityFilterChain bean "
						+ "or by adding a @Configuration that extends WebSecurityConfigurerAdapter. "
						+ "More advanced users can invoke " + WebSecurity.class.getSimpleName()
						+ ".addSecurityFilterChainBuilder directly");
		int chainSize = this.ignoredRequests.size() + this.securityFilterChainBuilders.size();
		List<SecurityFilterChain> securityFilterChains = new ArrayList<>(chainSize);
		for (RequestMatcher ignoredRequest : this.ignoredRequests) {
			securityFilterChains.add(new DefaultSecurityFilterChain(ignoredRequest));
		}
		for (SecurityBuilder<? extends SecurityFilterChain> securityFilterChainBuilder : this.securityFilterChainBuilders) {
			securityFilterChains.add(securityFilterChainBuilder.build());
		}
		FilterChainProxy filterChainProxy = new FilterChainProxy(securityFilterChains);
		if (this.httpFirewall != null) {
			filterChainProxy.setFirewall(this.httpFirewall);
		}
		if (this.requestRejectedHandler != null) {
			filterChainProxy.setRequestRejectedHandler(this.requestRejectedHandler);
		}
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
	}

	/**
	 * An {@link IgnoredRequestConfigurer} that allows optionally configuring the
	 * {@link MvcRequestMatcher#setMethod(HttpMethod)}
	 *
	 * @author Rob Winch
	 */
	public final class MvcMatchersIgnoredRequestConfigurer extends IgnoredRequestConfigurer {

		private final List<MvcRequestMatcher> mvcMatchers;

		private MvcMatchersIgnoredRequestConfigurer(ApplicationContext context, List<MvcRequestMatcher> mvcMatchers) {
			super(context);
			this.mvcMatchers = mvcMatchers;
		}

		public IgnoredRequestConfigurer servletPath(String servletPath) {
			for (MvcRequestMatcher matcher : this.mvcMatchers) {
				matcher.setServletPath(servletPath);
			}
			return this;
		}

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
		public MvcMatchersIgnoredRequestConfigurer mvcMatchers(HttpMethod method, String... mvcPatterns) {
			List<MvcRequestMatcher> mvcMatchers = createMvcMatchers(method, mvcPatterns);
			Arrays.asList(mvcPatterns).stream().forEach((t) -> printWarnSecurityMessage(method, t));
			mvcMatchers.stream().forEach((t) -> t.ignore());
			WebSecurity.this.ignoredRequests.addAll(mvcMatchers);
			return new MvcMatchersIgnoredRequestConfigurer(getApplicationContext(), mvcMatchers);
		}

		@Override
		public MvcMatchersIgnoredRequestConfigurer mvcMatchers(String... mvcPatterns) {
			return mvcMatchers(null, mvcPatterns);
		}

		/**
		 * @since 5.5
		 */
		@Override
		public IgnoredRequestConfigurer antMatchers(HttpMethod method) {
			return antMatchers(method, "/**");
		}

		/**
		 * @since 5.5
		 */
		@Override
		public IgnoredRequestConfigurer antMatchers(HttpMethod method, String... antPatterns) {
			Assert.state(!this.anyRequestConfigured, "Can't configure antMatchers after anyRequest");
			List<RequestMatcher> antMatchers = RequestMatchers.antMatchers(method, antPatterns);
			Arrays.asList(antPatterns).stream().forEach((t) -> printWarnSecurityMessage(method, t));
			antMatchers.stream().forEach((t) -> ((IgnoreRequestMatcher) t).ignore());
			return chainRequestMatchers(antMatchers);
		}

		/**
		 * @since 5.5
		 */
		@Override
		public IgnoredRequestConfigurer antMatchers(String... antPatterns) {
			Assert.state(!this.anyRequestConfigured, "Can't configure antMatchers after anyRequest");
			List<RequestMatcher> antMatchers = RequestMatchers.antMatchers(antPatterns);
			Arrays.asList(antPatterns).stream().forEach((t) -> printWarnSecurityMessage(null, t));
			antMatchers.stream().forEach((t) -> ((IgnoreRequestMatcher) t).ignore());
			return chainRequestMatchers(RequestMatchers.antMatchers(antPatterns));
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

		/**
		 * @param method the HttpMethod, it could be null too.
		 * @param pathPattern the path pattern to be ignored
		 * @since 5.5
		 */
		private void printWarnSecurityMessage(HttpMethod method, String pathPattern) {
			if (pathPattern.equals("/**")) {
				WebSecurity.this.logger
						.warn("**********************************************************************************");
				if (method != null) {
					WebSecurity.this.logger.warn(LogMessage.format(
							"Applying explicit instruction to ignore the '/**' path for the HttpMethod: %s", method));
					WebSecurity.this.logger.warn("You're disabling practically all the paths for that HttpMethod");
					WebSecurity.this.logger
							.warn("Therefore any path for that HttpMethod is completely ignored by Spring Security");
				}
				else {
					WebSecurity.this.logger.warn("Applying explicit instruction to ignore the '/**' path");
					WebSecurity.this.logger.warn("You're disabling practically all the paths");
					WebSecurity.this.logger.warn("Therefore any path is completely ignored by Spring Security");
				}
				WebSecurity.this.logger.warn("It is not recomended for production");
				WebSecurity.this.logger
						.warn("**********************************************************************************");
			}
		}

	}

}
