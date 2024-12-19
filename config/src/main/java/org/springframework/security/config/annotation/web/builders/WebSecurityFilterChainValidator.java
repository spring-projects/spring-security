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

package org.springframework.security.config.annotation.web.builders;

import java.util.List;

import jakarta.servlet.Filter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.UnreachableFilterChainException;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;

/**
 * A filter chain validator for filter chains built by {@link WebSecurity}
 *
 * @author Josh Cummings
 * @author Max Batischev
 * @since 6.5
 */
final class WebSecurityFilterChainValidator implements FilterChainProxy.FilterChainValidator {

	private final Log logger = LogFactory.getLog(getClass());

	@Override
	public void validate(FilterChainProxy filterChainProxy) {
		List<SecurityFilterChain> chains = filterChainProxy.getFilterChains();
		checkForAnyRequestRequestMatcher(chains);
		checkForDuplicateMatchers(chains);
		checkAuthorizationFilters(chains);
	}

	private void checkForAnyRequestRequestMatcher(List<SecurityFilterChain> chains) {
		DefaultSecurityFilterChain anyRequestFilterChain = null;
		for (SecurityFilterChain chain : chains) {
			if (anyRequestFilterChain != null) {
				String message = "A filter chain that matches any request [" + anyRequestFilterChain
						+ "] has already been configured, which means that this filter chain [" + chain
						+ "] will never get invoked. Please use `HttpSecurity#securityMatcher` to ensure that there is only one filter chain configured for 'any request' and that the 'any request' filter chain is published last.";
				throw new UnreachableFilterChainException(message, anyRequestFilterChain, chain);
			}
			if (chain instanceof DefaultSecurityFilterChain defaultChain) {
				if (defaultChain.getRequestMatcher() instanceof AnyRequestMatcher) {
					anyRequestFilterChain = defaultChain;
				}
			}
		}
	}

	private void checkForDuplicateMatchers(List<SecurityFilterChain> chains) {
		DefaultSecurityFilterChain filterChain = null;
		for (SecurityFilterChain chain : chains) {
			if (filterChain != null) {
				if (chain instanceof DefaultSecurityFilterChain defaultChain) {
					if (defaultChain.getRequestMatcher().equals(filterChain.getRequestMatcher())) {
						throw new UnreachableFilterChainException(
								"The FilterChainProxy contains two filter chains using the" + " matcher "
										+ defaultChain.getRequestMatcher(),
								filterChain, defaultChain);
					}
				}
			}
			if (chain instanceof DefaultSecurityFilterChain defaultChain) {
				filterChain = defaultChain;
			}
		}
	}

	private void checkAuthorizationFilters(List<SecurityFilterChain> chains) {
		Filter authorizationFilter = null;
		Filter filterSecurityInterceptor = null;
		for (SecurityFilterChain chain : chains) {
			for (Filter filter : chain.getFilters()) {
				if (filter instanceof AuthorizationFilter) {
					authorizationFilter = filter;
				}
				if (filter instanceof FilterSecurityInterceptor) {
					filterSecurityInterceptor = filter;
				}
			}
			if (authorizationFilter != null && filterSecurityInterceptor != null) {
				this.logger.warn(
						"It is not recommended to use authorizeRequests in the configuration. Please only use authorizeHttpRequests");
			}
			if (filterSecurityInterceptor != null) {
				this.logger.warn(
						"Usage of authorizeRequests is deprecated. Please use authorizeHttpRequests in the configuration");
			}
			authorizationFilter = null;
			filterSecurityInterceptor = null;
		}
	}

}
