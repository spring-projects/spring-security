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

package org.springframework.security.config.annotation.web;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jakarta.servlet.DispatcherType;

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
		List<RequestMatcher> matchers = new ArrayList<>();
		if (mvcPresent) {
			matchers.addAll(createMvcMatchers(method, patterns));
		}
		else {
			matchers.addAll(RequestMatchers.antMatchers(method, patterns));
		}
		return requestMatchers(matchers.toArray(new RequestMatcher[0]));
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
			String method = (httpMethod != null) ? httpMethod.toString() : null;
			List<RequestMatcher> matchers = new ArrayList<>();
			for (String pattern : antPatterns) {
				matchers.add(new AntPathRequestMatcher(pattern, method));
			}
			return matchers;
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

}
