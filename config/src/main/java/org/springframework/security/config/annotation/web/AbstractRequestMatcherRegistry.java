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

package org.springframework.security.config.annotation.web;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import jakarta.servlet.DispatcherType;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.DispatcherTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

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

	private static final RequestMatcher ANY_REQUEST = AnyRequestMatcher.INSTANCE;

	private ApplicationContext context;

	private boolean anyRequestConfigured = false;

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
	 * {@link AbstractRequestMatcherRegistry}
	 * @param requestMatchers the {@link RequestMatcher} instances
	 * @return the object that is chained after creating the {@link RequestMatcher}
	 */
	public C requestMatchers(RequestMatcher... requestMatchers) {
		Assert.state(!this.anyRequestConfigured, "Can't configure requestMatchers after anyRequest");
		return chainRequestMatchers(Arrays.asList(requestMatchers));
	}

	/**
	 * <p>
	 * Match when the {@link HttpMethod} is {@code method} and when the request URI
	 * matches one of {@code patterns}. See
	 * {@link org.springframework.web.util.pattern.PathPattern} for matching rules.
	 * </p>
	 * <p>
	 * If a specific {@link RequestMatcher} must be specified, use
	 * {@link #requestMatchers(RequestMatcher...)} instead
	 * </p>
	 * @param method the {@link HttpMethod} to use or {@code null} for any
	 * {@link HttpMethod}.
	 * @param patterns the patterns to match on
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
		Assert.state(!this.anyRequestConfigured, "Can't configure requestMatchers after anyRequest");
		PathPatternRequestMatcher.Builder builder = this.context.getBean(PathPatternRequestMatcher.Builder.class);
		List<RequestMatcher> matchers = new ArrayList<>();
		for (String pattern : patterns) {
			matchers.add(builder.matcher(method, pattern));
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

	/**
	 * <p>
	 * Match when the request URI matches one of {@code patterns}. See
	 * {@link org.springframework.web.util.pattern.PathPattern} for matching rules.
	 * </p>
	 * <p>
	 * If a specific {@link RequestMatcher} must be specified, use
	 * {@link #requestMatchers(RequestMatcher...)} instead
	 * </p>
	 * @param patterns the patterns to match on
	 * @return the object that is chained after creating the {@link RequestMatcher}.
	 * @since 5.8
	 */
	public C requestMatchers(String... patterns) {
		return requestMatchers(null, patterns);
	}

	/**
	 * <p>
	 * Match when the {@link HttpMethod} is {@code method}
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

}
