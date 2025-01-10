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

package org.springframework.security.config.annotation.web;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.ServletRegistrationsSupport.RegistrationMapping;
import org.springframework.security.config.annotation.web.configurers.AbstractConfigAttributeRequestMatcherRegistry;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.DispatcherTypeRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;
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
		ResolvableType type = ResolvableType.forClassWithGenerics(ObjectPostProcessor.class, Object.class);
		ObjectProvider<ObjectPostProcessor<Object>> postProcessors = this.context.getBeanProvider(type);
		ObjectPostProcessor<Object> opp = postProcessors.getObject();
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
		if (anyPathsDontStartWithLeadingSlash(patterns)) {
			this.logger.warn("One of the patterns in " + Arrays.toString(patterns)
					+ " is missing a leading slash. This is discouraged; please include the "
					+ "leading slash in all your request matcher patterns. In future versions of "
					+ "Spring Security, leaving out the leading slash will result in an exception.");
		}
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
		List<RequestMatcher> matchers = new ArrayList<>();
		for (String pattern : patterns) {
			AntPathRequestMatcher ant = new AntPathRequestMatcher(pattern, (method != null) ? method.name() : null);
			MvcRequestMatcher mvc = createMvcMatchers(method, pattern).get(0);
			matchers.add(new DeferredRequestMatcher((c) -> resolve(ant, mvc, c), mvc, ant));
		}
		return requestMatchers(matchers.toArray(new RequestMatcher[0]));
	}

	private boolean anyPathsDontStartWithLeadingSlash(String... patterns) {
		for (String pattern : patterns) {
			if (!pattern.startsWith("/")) {
				return true;
			}
		}
		return false;
	}

	private RequestMatcher resolve(AntPathRequestMatcher ant, MvcRequestMatcher mvc, ServletContext servletContext) {
		ServletRegistrationsSupport registrations = new ServletRegistrationsSupport(servletContext);
		Collection<RegistrationMapping> mappings = registrations.mappings();
		if (mappings.isEmpty()) {
			return new DispatcherServletDelegatingRequestMatcher(ant, mvc, new MockMvcRequestMatcher());
		}
		Collection<RegistrationMapping> dispatcherServletMappings = registrations.dispatcherServletMappings();
		if (dispatcherServletMappings.isEmpty()) {
			return new DispatcherServletDelegatingRequestMatcher(ant, mvc, new MockMvcRequestMatcher());
		}
		if (dispatcherServletMappings.size() > 1) {
			String errorMessage = computeErrorMessage(servletContext.getServletRegistrations().values());
			throw new IllegalArgumentException(errorMessage);
		}
		RegistrationMapping dispatcherServlet = dispatcherServletMappings.iterator().next();
		if (mappings.size() > 1 && !dispatcherServlet.isDefault()) {
			String errorMessage = computeErrorMessage(servletContext.getServletRegistrations().values());
			throw new IllegalArgumentException(errorMessage);
		}
		if (dispatcherServlet.isDefault()) {
			if (mappings.size() == 1) {
				return mvc;
			}
			return new DispatcherServletDelegatingRequestMatcher(ant, mvc);
		}
		return mvc;
	}

	private static String computeErrorMessage(Collection<? extends ServletRegistration> registrations) {
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

		final Function<ServletContext, RequestMatcher> requestMatcherFactory;

		final AtomicReference<String> description = new AtomicReference<>();

		final Map<ServletContext, RequestMatcher> requestMatchers = new ConcurrentHashMap<>();

		DeferredRequestMatcher(Function<ServletContext, RequestMatcher> resolver, RequestMatcher... candidates) {
			this.requestMatcherFactory = (sc) -> this.requestMatchers.computeIfAbsent(sc, resolver);
			this.description.set("Deferred " + Arrays.toString(candidates));
		}

		RequestMatcher requestMatcher(ServletContext servletContext) {
			return this.requestMatcherFactory.apply(servletContext);
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			return this.requestMatcherFactory.apply(request.getServletContext()).matches(request);
		}

		@Override
		public MatchResult matcher(HttpServletRequest request) {
			return this.requestMatcherFactory.apply(request.getServletContext()).matcher(request);
		}

		@Override
		public String toString() {
			return this.description.get();
		}

	}

	static class MockMvcRequestMatcher implements RequestMatcher {

		@Override
		public boolean matches(HttpServletRequest request) {
			return request.getAttribute("org.springframework.test.web.servlet.MockMvc.MVC_RESULT_ATTRIBUTE") != null;
		}

	}

	static class DispatcherServletRequestMatcher implements RequestMatcher {

		@Override
		public boolean matches(HttpServletRequest request) {
			String name = request.getHttpServletMapping().getServletName();
			ServletRegistration registration = request.getServletContext().getServletRegistration(name);
			Assert.notNull(registration,
					() -> computeErrorMessage(request.getServletContext().getServletRegistrations().values()));
			try {
				Class<?> clazz = Class.forName(registration.getClassName());
				return DispatcherServlet.class.isAssignableFrom(clazz);
			}
			catch (ClassNotFoundException ex) {
				return false;
			}
		}

	}

	static class DispatcherServletDelegatingRequestMatcher implements RequestMatcher {

		private final AntPathRequestMatcher ant;

		private final MvcRequestMatcher mvc;

		private final RequestMatcher dispatcherServlet;

		DispatcherServletDelegatingRequestMatcher(AntPathRequestMatcher ant, MvcRequestMatcher mvc) {
			this(ant, mvc, new OrRequestMatcher(new MockMvcRequestMatcher(), new DispatcherServletRequestMatcher()));
		}

		DispatcherServletDelegatingRequestMatcher(AntPathRequestMatcher ant, MvcRequestMatcher mvc,
				RequestMatcher dispatcherServlet) {
			this.ant = ant;
			this.mvc = mvc;
			this.dispatcherServlet = dispatcherServlet;
		}

		RequestMatcher requestMatcher(HttpServletRequest request) {
			if (this.dispatcherServlet.matches(request)) {
				return this.mvc;
			}
			return this.ant;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			return requestMatcher(request).matches(request);
		}

		@Override
		public MatchResult matcher(HttpServletRequest request) {
			return requestMatcher(request).matcher(request);
		}

		@Override
		public String toString() {
			return "DispatcherServletDelegating [" + "ant = " + this.ant + ", mvc = " + this.mvc + "]";
		}

	}

}
