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

package org.springframework.security.config.annotation.web;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.configurers.AbstractConfigAttributeRequestMatcherRegistry;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.DispatcherTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

/**
 * A base class for registering {@link RequestMatcher}'s. For example, it might allow for
 * specifying which {@link RequestMatcher} require a certain level of authorization.
 *
 * @param <C> The object that is returned or Chained after creating the RequestMatcher
 * @author Rob Winch
 * @author Ankur Pathak
 * @since 3.2
 */
public abstract class AbstractRequestMatcherRegistry<C> {

	private static final String HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME = "mvcHandlerMappingIntrospector";

	private static final String HANDLER_MAPPING_INTROSPECTOR = "org.springframework.web.servlet.handler.HandlerMappingIntrospector";

	private static final boolean mvcPresent;

	private static final RequestMatcher ANY_REQUEST = AnyRequestMatcher.INSTANCE;

	private ApplicationContext context;

	private boolean anyRequestConfigured = false;

	static {
		mvcPresent = ClassUtils.isPresent(HANDLER_MAPPING_INTROSPECTOR,
				AbstractRequestMatcherRegistry.class.getClassLoader());
	}

	private final Log logger = LogFactory.getLog(getClass());

	protected final void setApplicationContext(ApplicationContext context) {
		this.context = context;
	}

	/**
	 * Gets the {@link ApplicationContext}
	 * @return the {@link ApplicationContext}
	 */
	protected final ApplicationContext getApplicationContext() {
		return this.context;
	}

	/**
	 * Maps any request.
	 * @return the object that is chained after creating the {@link RequestMatcher}
	 */
	public C anyRequest() {
		Assert.state(!this.anyRequestConfigured, "Can't configure anyRequest after itself");
		C configurer = requestMatchers(ANY_REQUEST);
		this.anyRequestConfigured = true;
		return configurer;
	}

	/**
	 * Creates {@link MvcRequestMatcher} instances for the method and patterns passed in
	 * @param method the HTTP method to use or null if any should be used
	 * @param mvcPatterns the Spring MVC patterns to match on
	 * @return a List of {@link MvcRequestMatcher} instances
	 */
	protected final List<MvcRequestMatcher> createMvcMatchers(HttpMethod method, String... mvcPatterns) {
		Assert.state(!this.anyRequestConfigured, "Can't configure mvcMatchers after anyRequest");
		ObjectPostProcessor<Object> opp = this.context.getBean(ObjectPostProcessor.class);
		if (!this.context.containsBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME)) {
			throw new NoSuchBeanDefinitionException("A Bean named " + HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME
					+ " of type " + HandlerMappingIntrospector.class.getName()
					+ " is required to use MvcRequestMatcher. Please ensure Spring Security & Spring MVC are configured in a shared ApplicationContext.");
		}
		HandlerMappingIntrospector introspector = this.context.getBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME,
				HandlerMappingIntrospector.class);
		List<MvcRequestMatcher> matchers = new ArrayList<>(mvcPatterns.length);
		for (String mvcPattern : mvcPatterns) {
			MvcRequestMatcher matcher = new MvcRequestMatcher(introspector, mvcPattern);
			opp.postProcess(matcher);
			if (method != null) {
				matcher.setMethod(method);
			}
			matchers.add(matcher);
		}
		return matchers;
	}

	/**
	 * Maps a {@link List} of
	 * {@link org.springframework.security.web.util.matcher.DispatcherTypeRequestMatcher}
	 * instances.
	 * @param method the {@link HttpMethod} to use or {@code null} for any
	 * {@link HttpMethod}.
	 * @param dispatcherTypes the dispatcher types to match against
	 * @return the object that is chained after creating the {@link RequestMatcher}
	 */
	public C dispatcherTypeMatchers(@Nullable HttpMethod method, DispatcherType... dispatcherTypes) {
		Assert.state(!this.anyRequestConfigured, "Can't configure dispatcherTypeMatchers after anyRequest");
		List<RequestMatcher> matchers = new ArrayList<>();
		for (DispatcherType dispatcherType : dispatcherTypes) {
			matchers.add(new DispatcherTypeRequestMatcher(dispatcherType, method));
		}
		return chainRequestMatchers(matchers);
	}

	/**
	 * Create a {@link List} of
	 * {@link org.springframework.security.web.util.matcher.DispatcherTypeRequestMatcher}
	 * instances that do not specify an {@link HttpMethod}.
	 * @param dispatcherTypes the dispatcher types to match against
	 * @return the object that is chained after creating the {@link RequestMatcher}
	 */
	public C dispatcherTypeMatchers(DispatcherType... dispatcherTypes) {
		Assert.state(!this.anyRequestConfigured, "Can't configure dispatcherTypeMatchers after anyRequest");
		return dispatcherTypeMatchers(null, dispatcherTypes);
	}

	/**
	 * Associates a list of {@link RequestMatcher} instances with the
	 * {@link AbstractConfigAttributeRequestMatcherRegistry}
	 * @param requestMatchers the {@link RequestMatcher} instances
	 * @return the object that is chained after creating the {@link RequestMatcher}
	 */
	public C requestMatchers(RequestMatcher... requestMatchers) {
		Assert.state(!this.anyRequestConfigured, "Can't configure requestMatchers after anyRequest");
		return chainRequestMatchers(Arrays.asList(requestMatchers));
	}

	/**
	 * <p>
	 * If the {@link HandlerMappingIntrospector} is available in the classpath, maps to an
	 * {@link MvcRequestMatcher} that also specifies a specific {@link HttpMethod} to
	 * match on. This matcher will use the same rules that Spring MVC uses for matching.
	 * For example, often times a mapping of the path "/path" will match on "/path",
	 * "/path/", "/path.html", etc. If the {@link HandlerMappingIntrospector} is not
	 * available, maps to an {@link AntPathRequestMatcher}.
	 * </p>
	 * <p>
	 * If a specific {@link RequestMatcher} must be specified, use
	 * {@link #requestMatchers(RequestMatcher...)} instead
	 * </p>
	 * @param method the {@link HttpMethod} to use or {@code null} for any
	 * {@link HttpMethod}.
	 * @param patterns the patterns to match on. The rules for matching are defined by
	 * Spring MVC if {@link MvcRequestMatcher} is used
	 * @return the object that is chained after creating the {@link RequestMatcher}.
	 * @since 5.8
	 */
	public C requestMatchers(HttpMethod method, String... patterns) {
		if (!mvcPresent) {
			return requestMatchers(RequestMatchers.antMatchersAsArray(method, patterns));
		}
		if (!(this.context instanceof WebApplicationContext)) {
			return requestMatchers(RequestMatchers.antMatchersAsArray(method, patterns));
		}
		WebApplicationContext context = (WebApplicationContext) this.context;
		ServletContext servletContext = context.getServletContext();
		if (servletContext == null) {
			return requestMatchers(RequestMatchers.antMatchersAsArray(method, patterns));
		}
		boolean isProgrammaticApiAvailable = isProgrammaticApiAvailable(servletContext);
		List<RequestMatcher> matchers = new ArrayList<>();
		for (String pattern : patterns) {
			AntPathRequestMatcher ant = new AntPathRequestMatcher(pattern, (method != null) ? method.name() : null);
			MvcRequestMatcher mvc = createMvcMatchers(method, pattern).get(0);
			if (isProgrammaticApiAvailable) {
				matchers.add(resolve(ant, mvc, servletContext));
			}
			else {
				this.logger
					.warn("The ServletRegistration API was not available at startup time. This may be due to a misconfiguration; "
							+ "if you are using AbstractSecurityWebApplicationInitializer, please double-check the recommendations outlined in "
							+ "https://docs.spring.io/spring-security/reference/servlet/configuration/java.html#abstractsecuritywebapplicationinitializer-with-spring-mvc");
				matchers.add(new DeferredRequestMatcher((request) -> resolve(ant, mvc, request.getServletContext()),
						mvc, ant));
			}
		}
		return requestMatchers(matchers.toArray(new RequestMatcher[0]));
	}

	private static boolean isProgrammaticApiAvailable(ServletContext servletContext) {
		try {
			servletContext.getServletRegistrations();
			return true;
		}
		catch (UnsupportedOperationException ex) {
			return false;
		}
	}

	private RequestMatcher resolve(AntPathRequestMatcher ant, MvcRequestMatcher mvc, ServletContext servletContext) {
		Map<String, ? extends ServletRegistration> registrations = mappableServletRegistrations(servletContext);
		if (registrations.isEmpty()) {
			return ant;
		}
		if (!hasDispatcherServlet(registrations)) {
			return ant;
		}
		ServletRegistration dispatcherServlet = requireOneRootDispatcherServlet(registrations);
		if (dispatcherServlet != null) {
			if (registrations.size() == 1) {
				return mvc;
			}
			return new DispatcherServletDelegatingRequestMatcher(ant, mvc, servletContext);
		}
		dispatcherServlet = requireOnlyPathMappedDispatcherServlet(registrations);
		if (dispatcherServlet != null) {
			String mapping = dispatcherServlet.getMappings().iterator().next();
			mvc.setServletPath(mapping.substring(0, mapping.length() - 2));
			return mvc;
		}
		String errorMessage = computeErrorMessage(registrations.values());
		throw new IllegalArgumentException(errorMessage);
	}

	private Map<String, ? extends ServletRegistration> mappableServletRegistrations(ServletContext servletContext) {
		Map<String, ServletRegistration> mappable = new LinkedHashMap<>();
		for (Map.Entry<String, ? extends ServletRegistration> entry : servletContext.getServletRegistrations()
			.entrySet()) {
			if (!entry.getValue().getMappings().isEmpty()) {
				mappable.put(entry.getKey(), entry.getValue());
			}
		}
		return mappable;
	}

	private boolean hasDispatcherServlet(Map<String, ? extends ServletRegistration> registrations) {
		if (registrations == null) {
			return false;
		}
		for (ServletRegistration registration : registrations.values()) {
			if (isDispatcherServlet(registration)) {
				return true;
			}
		}
		return false;
	}

	private ServletRegistration requireOneRootDispatcherServlet(
			Map<String, ? extends ServletRegistration> registrations) {
		ServletRegistration rootDispatcherServlet = null;
		for (ServletRegistration registration : registrations.values()) {
			if (!isDispatcherServlet(registration)) {
				continue;
			}
			if (registration.getMappings().size() > 1) {
				return null;
			}
			if (!"/".equals(registration.getMappings().iterator().next())) {
				return null;
			}
			rootDispatcherServlet = registration;
		}
		return rootDispatcherServlet;
	}

	private ServletRegistration requireOnlyPathMappedDispatcherServlet(
			Map<String, ? extends ServletRegistration> registrations) {
		ServletRegistration pathDispatcherServlet = null;
		for (ServletRegistration registration : registrations.values()) {
			if (!isDispatcherServlet(registration)) {
				return null;
			}
			if (registration.getMappings().size() > 1) {
				return null;
			}
			String mapping = registration.getMappings().iterator().next();
			if (!mapping.startsWith("/") || !mapping.endsWith("/*")) {
				return null;
			}
			if (pathDispatcherServlet != null) {
				return null;
			}
			pathDispatcherServlet = registration;
		}
		return pathDispatcherServlet;
	}

	private boolean isDispatcherServlet(ServletRegistration registration) {
		Class<?> dispatcherServlet = ClassUtils.resolveClassName("org.springframework.web.servlet.DispatcherServlet",
				null);
		try {
			Class<?> clazz = Class.forName(registration.getClassName());
			return dispatcherServlet.isAssignableFrom(clazz);
		}
		catch (ClassNotFoundException ex) {
			return false;
		}
	}

	private String computeErrorMessage(Collection<? extends ServletRegistration> registrations) {
		String template = "This method cannot decide whether these patterns are Spring MVC patterns or not. "
				+ "If this endpoint is a Spring MVC endpoint, please use requestMatchers(MvcRequestMatcher); "
				+ "otherwise, please use requestMatchers(AntPathRequestMatcher).\n\n"
				+ "This is because there is more than one mappable servlet in your servlet context: %s.\n\n"
				+ "For each MvcRequestMatcher, call MvcRequestMatcher#setServletPath to indicate the servlet path.";
		Map<String, Collection<String>> mappings = new LinkedHashMap<>();
		for (ServletRegistration registration : registrations) {
			mappings.put(registration.getClassName(), registration.getMappings());
		}
		return String.format(template, mappings);
	}

	/**
	 * <p>
	 * If the {@link HandlerMappingIntrospector} is available in the classpath, maps to an
	 * {@link MvcRequestMatcher} that does not care which {@link HttpMethod} is used. This
	 * matcher will use the same rules that Spring MVC uses for matching. For example,
	 * often times a mapping of the path "/path" will match on "/path", "/path/",
	 * "/path.html", etc. If the {@link HandlerMappingIntrospector} is not available, maps
	 * to an {@link AntPathRequestMatcher}.
	 * </p>
	 * <p>
	 * If a specific {@link RequestMatcher} must be specified, use
	 * {@link #requestMatchers(RequestMatcher...)} instead
	 * </p>
	 * @param patterns the patterns to match on. The rules for matching are defined by
	 * Spring MVC if {@link MvcRequestMatcher} is used
	 * @return the object that is chained after creating the {@link RequestMatcher}.
	 * @since 5.8
	 */
	public C requestMatchers(String... patterns) {
		return requestMatchers(null, patterns);
	}

	/**
	 * <p>
	 * If the {@link HandlerMappingIntrospector} is available in the classpath, maps to an
	 * {@link MvcRequestMatcher} that matches on a specific {@link HttpMethod}. This
	 * matcher will use the same rules that Spring MVC uses for matching. For example,
	 * often times a mapping of the path "/path" will match on "/path", "/path/",
	 * "/path.html", etc. If the {@link HandlerMappingIntrospector} is not available, maps
	 * to an {@link AntPathRequestMatcher}.
	 * </p>
	 * <p>
	 * If a specific {@link RequestMatcher} must be specified, use
	 * {@link #requestMatchers(RequestMatcher...)} instead
	 * </p>
	 * @param method the {@link HttpMethod} to use or {@code null} for any
	 * {@link HttpMethod}.
	 * @return the object that is chained after creating the {@link RequestMatcher}.
	 * @since 5.8
	 */
	public C requestMatchers(HttpMethod method) {
		return requestMatchers(method, "/**");
	}

	/**
	 * Subclasses should implement this method for returning the object that is chained to
	 * the creation of the {@link RequestMatcher} instances.
	 * @param requestMatchers the {@link RequestMatcher} instances that were created
	 * @return the chained Object for the subclass which allows association of something
	 * else to the {@link RequestMatcher}
	 */
	protected abstract C chainRequestMatchers(List<RequestMatcher> requestMatchers);

	/**
	 * Utilities for creating {@link RequestMatcher} instances.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	private static final class RequestMatchers {

		private RequestMatchers() {
		}

		/**
		 * Create a {@link List} of {@link AntPathRequestMatcher} instances.
		 * @param httpMethod the {@link HttpMethod} to use or {@code null} for any
		 * {@link HttpMethod}.
		 * @param antPatterns the ant patterns to create {@link AntPathRequestMatcher}
		 * from
		 * @return a {@link List} of {@link AntPathRequestMatcher} instances
		 */
		static List<RequestMatcher> antMatchers(HttpMethod httpMethod, String... antPatterns) {
			return Arrays.asList(antMatchersAsArray(httpMethod, antPatterns));
		}

		/**
		 * Create a {@link List} of {@link AntPathRequestMatcher} instances that do not
		 * specify an {@link HttpMethod}.
		 * @param antPatterns the ant patterns to create {@link AntPathRequestMatcher}
		 * from
		 * @return a {@link List} of {@link AntPathRequestMatcher} instances
		 */
		static List<RequestMatcher> antMatchers(String... antPatterns) {
			return antMatchers(null, antPatterns);
		}

		static RequestMatcher[] antMatchersAsArray(HttpMethod httpMethod, String... antPatterns) {
			String method = (httpMethod != null) ? httpMethod.toString() : null;
			RequestMatcher[] matchers = new RequestMatcher[antPatterns.length];
			for (int index = 0; index < antPatterns.length; index++) {
				matchers[index] = new AntPathRequestMatcher(antPatterns[index], method);
			}
			return matchers;
		}

		/**
		 * Create a {@link List} of {@link RegexRequestMatcher} instances.
		 * @param httpMethod the {@link HttpMethod} to use or {@code null} for any
		 * {@link HttpMethod}.
		 * @param regexPatterns the regular expressions to create
		 * {@link RegexRequestMatcher} from
		 * @return a {@link List} of {@link RegexRequestMatcher} instances
		 */
		static List<RequestMatcher> regexMatchers(HttpMethod httpMethod, String... regexPatterns) {
			String method = (httpMethod != null) ? httpMethod.toString() : null;
			List<RequestMatcher> matchers = new ArrayList<>();
			for (String pattern : regexPatterns) {
				matchers.add(new RegexRequestMatcher(pattern, method));
			}
			return matchers;
		}

		/**
		 * Create a {@link List} of {@link RegexRequestMatcher} instances that do not
		 * specify an {@link HttpMethod}.
		 * @param regexPatterns the regular expressions to create
		 * {@link RegexRequestMatcher} from
		 * @return a {@link List} of {@link RegexRequestMatcher} instances
		 */
		static List<RequestMatcher> regexMatchers(String... regexPatterns) {
			return regexMatchers(null, regexPatterns);
		}

	}

	static class DeferredRequestMatcher implements RequestMatcher {

		final Function<HttpServletRequest, RequestMatcher> requestMatcherFactory;

		final AtomicReference<String> description = new AtomicReference<>();

		volatile RequestMatcher requestMatcher;

		DeferredRequestMatcher(Function<HttpServletRequest, RequestMatcher> resolver, RequestMatcher... candidates) {
			this.requestMatcherFactory = (request) -> {
				if (this.requestMatcher == null) {
					synchronized (this) {
						if (this.requestMatcher == null) {
							this.requestMatcher = resolver.apply(request);
						}
					}
				}
				return this.requestMatcher;
			};
			this.description.set("Deferred " + Arrays.toString(candidates));
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			return this.requestMatcherFactory.apply(request).matches(request);
		}

		@Override
		public MatchResult matcher(HttpServletRequest request) {
			return this.requestMatcherFactory.apply(request).matcher(request);
		}

		@Override
		public String toString() {
			return this.description.get();
		}

	}

	static class DispatcherServletDelegatingRequestMatcher implements RequestMatcher {

		private final AntPathRequestMatcher ant;

		private final MvcRequestMatcher mvc;

		private final ServletContext servletContext;

		DispatcherServletDelegatingRequestMatcher(AntPathRequestMatcher ant, MvcRequestMatcher mvc,
				ServletContext servletContext) {
			this.ant = ant;
			this.mvc = mvc;
			this.servletContext = servletContext;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			String name = request.getHttpServletMapping().getServletName();
			ServletRegistration registration = this.servletContext.getServletRegistration(name);
			Assert.notNull(registration, "Failed to find servlet [" + name + "] in the servlet context");
			if (isDispatcherServlet(registration)) {
				return this.mvc.matches(request);
			}
			return this.ant.matches(request);
		}

		@Override
		public MatchResult matcher(HttpServletRequest request) {
			String name = request.getHttpServletMapping().getServletName();
			ServletRegistration registration = this.servletContext.getServletRegistration(name);
			Assert.notNull(registration, "Failed to find servlet [" + name + "] in the servlet context");
			if (isDispatcherServlet(registration)) {
				return this.mvc.matcher(request);
			}
			return this.ant.matcher(request);
		}

		private boolean isDispatcherServlet(ServletRegistration registration) {
			Class<?> dispatcherServlet = ClassUtils
				.resolveClassName("org.springframework.web.servlet.DispatcherServlet", null);
			try {
				Class<?> clazz = Class.forName(registration.getClassName());
				return dispatcherServlet.isAssignableFrom(clazz);
			}
			catch (ClassNotFoundException ex) {
				return false;
			}
		}

		@Override
		public String toString() {
			return "DispatcherServletDelegating [" + "ant = " + this.ant + ", mvc = " + this.mvc + "]";
		}

	}

}
