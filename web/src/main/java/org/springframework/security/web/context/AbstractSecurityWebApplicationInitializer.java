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

package org.springframework.security.web.context;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterRegistration.Dynamic;
import jakarta.servlet.ServletContext;
import jakarta.servlet.SessionTrackingMode;

import org.springframework.context.ApplicationContext;
import org.springframework.core.Conventions;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.util.Assert;
import org.springframework.web.WebApplicationInitializer;
import org.springframework.web.context.AbstractContextLoaderInitializer;
import org.springframework.web.context.ContextLoaderListener;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.filter.DelegatingFilterProxy;

/**
 * Registers the {@link DelegatingFilterProxy} to use the springSecurityFilterChain before
 * any other registered {@link Filter}. When used with
 * {@link #AbstractSecurityWebApplicationInitializer(Class...)}, it will also register a
 * {@link ContextLoaderListener}. When used with
 * {@link #AbstractSecurityWebApplicationInitializer()}, this class is typically used in
 * addition to a subclass of {@link AbstractContextLoaderInitializer}.
 *
 * <p>
 * By default the {@link DelegatingFilterProxy} is registered without support, but can be
 * enabled by overriding {@link #isAsyncSecuritySupported()} and
 * {@link #getSecurityDispatcherTypes()}.
 * </p>
 *
 * <p>
 * Additional configuration before and after the springSecurityFilterChain can be added by
 * overriding {@link #afterSpringSecurityFilterChain(ServletContext)}.
 * </p>
 *
 *
 * <h2>Caveats</h2>
 * <p>
 * Subclasses of AbstractDispatcherServletInitializer will register their filters before
 * any other {@link Filter}. This means that you will typically want to ensure subclasses
 * of AbstractDispatcherServletInitializer are invoked first. This can be done by ensuring
 * the {@link Order} or {@link Ordered} of AbstractDispatcherServletInitializer are sooner
 * than subclasses of {@link AbstractSecurityWebApplicationInitializer}.
 * </p>
 *
 * @author Rob Winch
 * @author Keesun Baik
 */
public abstract class AbstractSecurityWebApplicationInitializer implements WebApplicationInitializer {

	private static final String SERVLET_CONTEXT_PREFIX = "org.springframework.web.servlet.FrameworkServlet.CONTEXT.";

	public static final String DEFAULT_FILTER_NAME = "springSecurityFilterChain";

	private final Class<?>[] configurationClasses;

	/**
	 * Creates a new instance that assumes the Spring Security configuration is loaded by
	 * some other means than this class. For example, a user might create a
	 * {@link ContextLoaderListener} using a subclass of
	 * {@link AbstractContextLoaderInitializer}.
	 *
	 * @see ContextLoaderListener
	 */
	protected AbstractSecurityWebApplicationInitializer() {
		this.configurationClasses = null;
	}

	/**
	 * Creates a new instance that will instantiate the {@link ContextLoaderListener} with
	 * the specified classes.
	 * @param configurationClasses
	 */
	protected AbstractSecurityWebApplicationInitializer(Class<?>... configurationClasses) {
		this.configurationClasses = configurationClasses;
	}

	@Override
	public final void onStartup(ServletContext servletContext) {
		beforeSpringSecurityFilterChain(servletContext);
		if (this.configurationClasses != null) {
			AnnotationConfigWebApplicationContext rootAppContext = new AnnotationConfigWebApplicationContext();
			rootAppContext.register(this.configurationClasses);
			servletContext.addListener(new ContextLoaderListener(rootAppContext));
		}
		if (enableHttpSessionEventPublisher()) {
			servletContext.addListener("org.springframework.security.web.session.HttpSessionEventPublisher");
		}
		servletContext.setSessionTrackingModes(getSessionTrackingModes());
		insertSpringSecurityFilterChain(servletContext);
		afterSpringSecurityFilterChain(servletContext);
	}

	/**
	 * Override this if {@link HttpSessionEventPublisher} should be added as a listener.
	 * This should be true, if session management has specified a maximum number of
	 * sessions.
	 * @return true to add {@link HttpSessionEventPublisher}, else false
	 */
	protected boolean enableHttpSessionEventPublisher() {
		return false;
	}

	/**
	 * Registers the springSecurityFilterChain
	 * @param servletContext the {@link ServletContext}
	 */
	private void insertSpringSecurityFilterChain(ServletContext servletContext) {
		String filterName = DEFAULT_FILTER_NAME;
		DelegatingFilterProxy springSecurityFilterChain = new DelegatingFilterProxy(filterName);
		String contextAttribute = getWebApplicationContextAttribute();
		if (contextAttribute != null) {
			springSecurityFilterChain.setContextAttribute(contextAttribute);
		}
		registerFilter(servletContext, true, filterName, springSecurityFilterChain);
	}

	/**
	 * Inserts the provided {@link Filter}s before existing {@link Filter}s using default
	 * generated names, {@link #getSecurityDispatcherTypes()}, and
	 * {@link #isAsyncSecuritySupported()}.
	 * @param servletContext the {@link ServletContext} to use
	 * @param filters the {@link Filter}s to register
	 */
	protected final void insertFilters(ServletContext servletContext, Filter... filters) {
		registerFilters(servletContext, true, filters);
	}

	/**
	 * Inserts the provided {@link Filter}s after existing {@link Filter}s using default
	 * generated names, {@link #getSecurityDispatcherTypes()}, and
	 * {@link #isAsyncSecuritySupported()}.
	 * @param servletContext the {@link ServletContext} to use
	 * @param filters the {@link Filter}s to register
	 */
	protected final void appendFilters(ServletContext servletContext, Filter... filters) {
		registerFilters(servletContext, false, filters);
	}

	/**
	 * Registers the provided {@link Filter}s using default generated names,
	 * {@link #getSecurityDispatcherTypes()}, and {@link #isAsyncSecuritySupported()}.
	 * @param servletContext the {@link ServletContext} to use
	 * @param insertBeforeOtherFilters if true, will insert the provided {@link Filter}s
	 * before other {@link Filter}s. Otherwise, will insert the {@link Filter}s after
	 * other {@link Filter}s.
	 * @param filters the {@link Filter}s to register
	 */
	private void registerFilters(ServletContext servletContext, boolean insertBeforeOtherFilters, Filter... filters) {
		Assert.notEmpty(filters, "filters cannot be null or empty");
		for (Filter filter : filters) {
			Assert.notNull(filter, () -> "filters cannot contain null values. Got " + Arrays.asList(filters));
			String filterName = Conventions.getVariableName(filter);
			registerFilter(servletContext, insertBeforeOtherFilters, filterName, filter);
		}
	}

	/**
	 * Registers the provided filter using the {@link #isAsyncSecuritySupported()} and
	 * {@link #getSecurityDispatcherTypes()}.
	 * @param servletContext
	 * @param insertBeforeOtherFilters should this Filter be inserted before or after
	 * other {@link Filter}
	 * @param filterName
	 * @param filter
	 */
	private void registerFilter(ServletContext servletContext, boolean insertBeforeOtherFilters, String filterName,
			Filter filter) {
		Dynamic registration = servletContext.addFilter(filterName, filter);
		Assert.state(registration != null, () -> "Duplicate Filter registration for '" + filterName
				+ "'. Check to ensure the Filter is only configured once.");
		registration.setAsyncSupported(isAsyncSecuritySupported());
		EnumSet<DispatcherType> dispatcherTypes = getSecurityDispatcherTypes();
		registration.addMappingForUrlPatterns(dispatcherTypes, !insertBeforeOtherFilters, "/*");
	}

	/**
	 * Returns the {@link DelegatingFilterProxy#getContextAttribute()} or null if the
	 * parent {@link ApplicationContext} should be used. The default behavior is to use
	 * the parent {@link ApplicationContext}.
	 *
	 * <p>
	 * If {@link #getDispatcherWebApplicationContextSuffix()} is non-null the
	 * {@link WebApplicationContext} for the Dispatcher will be used. This means the child
	 * {@link ApplicationContext} is used to look up the springSecurityFilterChain bean.
	 * </p>
	 * @return the {@link DelegatingFilterProxy#getContextAttribute()} or null if the
	 * parent {@link ApplicationContext} should be used
	 */
	private String getWebApplicationContextAttribute() {
		String dispatcherServletName = getDispatcherWebApplicationContextSuffix();
		if (dispatcherServletName == null) {
			return null;
		}
		return SERVLET_CONTEXT_PREFIX + dispatcherServletName;
	}

	/**
	 * Determines how a session should be tracked. By default,
	 * {@link SessionTrackingMode#COOKIE} is used.
	 *
	 * <p>
	 * Note that {@link SessionTrackingMode#URL} is intentionally omitted to help
	 * protected against <a href="https://en.wikipedia.org/wiki/Session_fixation">session
	 * fixation attacks</a>. {@link SessionTrackingMode#SSL} is omitted because SSL
	 * configuration is required for this to work.
	 * </p>
	 *
	 * <p>
	 * Subclasses can override this method to make customizations.
	 * </p>
	 * @return
	 */
	protected Set<SessionTrackingMode> getSessionTrackingModes() {
		return EnumSet.of(SessionTrackingMode.COOKIE);
	}

	/**
	 * Return the &lt;servlet-name&gt; to use the DispatcherServlet's
	 * {@link WebApplicationContext} to find the {@link DelegatingFilterProxy} or null to
	 * use the parent {@link ApplicationContext}.
	 *
	 * <p>
	 * For example, if you are using AbstractDispatcherServletInitializer or
	 * AbstractAnnotationConfigDispatcherServletInitializer and using the provided Servlet
	 * name, you can return "dispatcher" from this method to use the DispatcherServlet's
	 * {@link WebApplicationContext}.
	 * </p>
	 * @return the &lt;servlet-name&gt; of the DispatcherServlet to use its
	 * {@link WebApplicationContext} or null (default) to use the parent
	 * {@link ApplicationContext}.
	 */
	protected String getDispatcherWebApplicationContextSuffix() {
		return null;
	}

	/**
	 * Invoked before the springSecurityFilterChain is added.
	 * @param servletContext the {@link ServletContext}
	 */
	protected void beforeSpringSecurityFilterChain(ServletContext servletContext) {

	}

	/**
	 * Invoked after the springSecurityFilterChain is added.
	 * @param servletContext the {@link ServletContext}
	 */
	protected void afterSpringSecurityFilterChain(ServletContext servletContext) {

	}

	/**
	 * Get the {@link DispatcherType} for the springSecurityFilterChain.
	 * @return
	 */
	protected EnumSet<DispatcherType> getSecurityDispatcherTypes() {
		return EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR, DispatcherType.ASYNC, DispatcherType.FORWARD,
				DispatcherType.INCLUDE);
	}

	/**
	 * Determine if the springSecurityFilterChain should be marked as supporting async.
	 * Default is true.
	 * @return true if springSecurityFilterChain should be marked as supporting async
	 */
	protected boolean isAsyncSecuritySupported() {
		return true;
	}

}
