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

package org.springframework.security.config.annotation.web.configurers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.web.servlet.DispatcherServlet;

/**
 * A factory for constructing {@link RequestMatcherBuilder} instances
 *
 * @author Josh Cummings
 * @since 6.2
 */
final class RequestMatcherBuilders {

	private static final String HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME = "mvcHandlerMappingIntrospector";

	private static final String HANDLER_MAPPING_INTROSPECTOR = "org.springframework.web.servlet.handler.HandlerMappingIntrospector";

	private static final boolean mvcPresent;

	static {
		mvcPresent = ClassUtils.isPresent(HANDLER_MAPPING_INTROSPECTOR, RequestMatcherBuilders.class.getClassLoader());
	}

	private static final Log logger = LogFactory.getLog(RequestMatcherBuilders.class);

	private RequestMatcherBuilders() {

	}

	/**
	 * Create the default {@link RequestMatcherBuilder} for use by Spring Security DSLs.
	 *
	 * <p>
	 * If Spring MVC is not present on the classpath or if there is no
	 * {@link DispatcherServlet}, this method will return an Ant-based builder.
	 *
	 * <p>
	 * If the servlet configuration has only {@link DispatcherServlet} with a single
	 * mapping (for example `/` or `/path/*`), then this method will return an MVC-based
	 * builder.
	 *
	 * <p>
	 * If the servlet configuration maps {@link DispatcherServlet} to a path and also has
	 * other servlets, this will throw an exception. In that case, an application should
	 * instead use the {@link RequestMatcherBuilders#createForServletPattern} ideally with
	 * the associated
	 * {@link org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer}
	 * to create builders by servlet path.
	 *
	 * <p>
	 * Otherwise, (namely if {@link DispatcherServlet} is root), this method will return a
	 * builder that delegates to an Ant or Mvc builder at runtime.
	 * @param context the application context
	 * @return the appropriate {@link RequestMatcherBuilder} based on application
	 * configuration
	 */
	static RequestMatcherBuilder createDefault(ApplicationContext context) {
		if (!mvcPresent) {
			logger.trace("Defaulting to Ant matching since Spring MVC is not on the classpath");
			return AntPathRequestMatcherBuilder.absolute();
		}
		if (!context.containsBean(HANDLER_MAPPING_INTROSPECTOR_BEAN_NAME)) {
			logger.trace("Defaulting to Ant matching since Spring MVC is not fully configured");
			return AntPathRequestMatcherBuilder.absolute();
		}
		ServletRegistrationCollection registrations = ServletRegistrationCollection.registrations(context);
		if (registrations.isEmpty()) {
			logger.trace("Defaulting to MVC matching since Spring MVC is on the class path and no servlet "
					+ "information is available");
			return AntPathRequestMatcherBuilder.absolute();
		}
		ServletRegistrationCollection dispatcherServlets = registrations.dispatcherServlets();
		if (dispatcherServlets.isEmpty()) {
			logger.trace("Defaulting to Ant matching since there is no DispatcherServlet configured");
			return AntPathRequestMatcherBuilder.absolute();
		}
		ServletRegistrationCollection.ServletPath servletPath = registrations.deduceOneServletPath();
		if (servletPath != null) {
			String message = "Defaulting to MVC matching since DispatcherServlet [%s] is the only servlet mapping";
			logger.trace(String.format(message, servletPath.path()));
			return MvcRequestMatcherBuilder.relativeTo(context, servletPath.path());
		}
		servletPath = dispatcherServlets.deduceOneServletPath();
		if (servletPath == null) {
			logger.trace("Did not choose a default since there is more than one DispatcherServlet mapping");
			String message = String.format("""
					This method cannot decide whether these patterns are Spring MVC patterns or not
					since your servlet configuration has multiple Spring MVC servlet mappings.

					For your reference, here is your servlet configuration: %s

					To address this, you need to specify the servlet path for each endpoint.
					You can use .forServletPattern in conjunction with requestMatchers do to this
					like so:

					@Bean
					SecurityFilterChain appSecurity(HttpSecurity http) throws Exception {
						http
							.authorizeHttpRequests((authorize) -> authorize
								.forServletPattern("/mvc-one/*", (one) -> one
									.requestMatchers("/controller/**", "/endpoints/**"
								)...
								.forServletPattern("/mvc-two/*", (two) -> two
									.requestMatchers("/other/**", "/controllers/**")...
								)
								.forServletPattern("/h2-console/*", (h2) -> h2
									.requestMatchers("/**")...
								)
							)
							// ...
						return http.build();
					}
					""", registrations);
			return new ErrorRequestMatcherBuilder(message);
		}
		if (servletPath.path() != null) {
			logger.trace("Did not choose a default since there is a non-root DispatcherServlet mapping");
			String message = String.format("""
					This method cannot decide whether these patterns are Spring MVC patterns or not
					since your Spring MVC mapping is mapped to a path and you have other servlet mappings.

					For your reference, here is your servlet configuration: %s

					To address this, you need to specify the servlet path for each endpoint.
					You can use .forServletPattern in conjunction with requestMatchers do to this
					like so:

					@Bean
					SecurityFilterChain appSecurity(HttpSecurity http) throws Exception {
						http
							.authorizeHttpRequests((authorize) -> authorize
								.forServletPattern("/mvc/*", (mvc) -> mvc
									.requestMatchers("/controller/**", "/endpoints/**")...
								)
								.forServletPattern("/h2-console/*", (h2) -> h2
									.requestMatchers("/**")...
								)
							)
							// ...
						return http.build();
					}
					""", registrations);
			return new ErrorRequestMatcherBuilder(message);
		}
		logger.trace("Defaulting to request-time checker since DispatcherServlet is mapped to root, but there are also "
				+ "other servlet mappings");
		return new DispatcherServletDelegatingRequestMatcherBuilder(MvcRequestMatcherBuilder.absolute(context),
				AntPathRequestMatcherBuilder.absolute(), registrations);
	}

	static RequestMatcherBuilder createForServletPattern(ApplicationContext context, String pattern) {
		Assert.notNull(pattern, "pattern cannot be null");
		ServletRegistrationCollection registrations = ServletRegistrationCollection.registrations(context);
		ServletRegistrationCollection.Registration registration = registrations.registrationByMapping(pattern);
		Assert.notNull(registration, () -> String
			.format("The given pattern %s doesn't seem to match any configured servlets: %s", pattern, registrations));
		boolean isPathPattern = pattern.startsWith("/") && pattern.endsWith("/*");
		if (isPathPattern) {
			String path = pattern.substring(0, pattern.length() - 2);
			return (registration.isDispatcherServlet()) ? MvcRequestMatcherBuilder.relativeTo(context, path)
					: AntPathRequestMatcherBuilder.relativeTo(path);
		}
		return (registration.isDispatcherServlet()) ? MvcRequestMatcherBuilder.absolute(context)
				: AntPathRequestMatcherBuilder.absolute();
	}

	private static class ErrorRequestMatcherBuilder implements RequestMatcherBuilder {

		private final String errorMessage;

		ErrorRequestMatcherBuilder(String errorMessage) {
			this.errorMessage = errorMessage;
		}

		@Override
		public RequestMatcher matcher(String pattern) {
			throw new IllegalArgumentException(this.errorMessage);
		}

		@Override
		public RequestMatcher matcher(HttpMethod method, String pattern) {
			throw new IllegalArgumentException(this.errorMessage);
		}

		@Override
		public RequestMatcher any() {
			throw new IllegalArgumentException(this.errorMessage);
		}

	}

}
