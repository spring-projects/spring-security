/*
 * Copyright 2002-2013 the original author or authors.
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

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.access.SecurityConfig;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractConfigAttributeRequestMatcherRegistry.UrlMapping;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Configures non-null URL's to grant access to every URL
 * @author Rob Winch
 * @since 3.2
 */
final class PermitAllSupport {

	public static void permitAll(
			HttpSecurityBuilder<? extends HttpSecurityBuilder<?>> http, String... urls) {
		for (String url : urls) {
			if (url != null) {
				permitAll(http, new ExactUrlRequestMatcher(url));
			}
		}
	}

	@SuppressWarnings("unchecked")
	public static void permitAll(
			HttpSecurityBuilder<? extends HttpSecurityBuilder<?>> http,
			RequestMatcher... requestMatchers) {
		ExpressionUrlAuthorizationConfigurer<?> configurer = http
				.getConfigurer(ExpressionUrlAuthorizationConfigurer.class);

		if (configurer == null) {
			throw new IllegalStateException(
					"permitAll only works with HttpSecurity.authorizeRequests()");
		}

		for (RequestMatcher matcher : requestMatchers) {
			if (matcher != null) {
				configurer
						.getRegistry()
						.addMapping(
								0,
								new UrlMapping(
										matcher,
										SecurityConfig
												.createList(ExpressionUrlAuthorizationConfigurer.permitAll)));
			}
		}
	}

	private final static class ExactUrlRequestMatcher implements RequestMatcher {
		private String processUrl;

		private ExactUrlRequestMatcher(String processUrl) {
			this.processUrl = processUrl;
		}

		public boolean matches(HttpServletRequest request) {
			String uri = request.getRequestURI();
			String query = request.getQueryString();

			if (query != null) {
				uri += "?" + query;
			}

			if ("".equals(request.getContextPath())) {
				return uri.equals(processUrl);
			}

			return uri.equals(request.getContextPath() + processUrl);
		}

		@Override
		public String toString() {
			StringBuilder sb = new StringBuilder();
			sb.append("ExactUrl [processUrl='").append(processUrl).append("']");
			return sb.toString();
		}
	}

	private PermitAllSupport() {
	}
}