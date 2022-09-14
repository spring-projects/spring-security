/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.test.web.servlet.setup;

import java.io.IOException;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;

import org.springframework.security.config.BeanIds;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.ConfigurableMockMvcBuilder;
import org.springframework.test.web.servlet.setup.MockMvcConfigurerAdapter;
import org.springframework.util.Assert;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.testSecurityContext;

/**
 * Configures Spring Security by adding the springSecurityFilterChain and adding the
 * {@link org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors#testSecurityContext()}
 * .
 *
 * @author Rob Winch
 * @since 4.0
 */
final class SecurityMockMvcConfigurer extends MockMvcConfigurerAdapter {

	private final DelegateFilter delegateFilter;

	/**
	 * Creates a new instance
	 */
	SecurityMockMvcConfigurer() {
		this.delegateFilter = new DelegateFilter();
	}

	/**
	 * Creates a new instance with the provided {@link jakarta.servlet.Filter}
	 * @param springSecurityFilterChain the {@link jakarta.servlet.Filter} to use
	 */
	SecurityMockMvcConfigurer(Filter springSecurityFilterChain) {
		this.delegateFilter = new DelegateFilter(springSecurityFilterChain);
	}

	@Override
	public void afterConfigurerAdded(ConfigurableMockMvcBuilder<?> builder) {
		builder.addFilters(this.delegateFilter);
	}

	@Override
	public RequestPostProcessor beforeMockMvcCreated(ConfigurableMockMvcBuilder<?> builder,
			WebApplicationContext context) {
		String securityBeanId = BeanIds.SPRING_SECURITY_FILTER_CHAIN;
		if (getSpringSecurityFilterChain() == null && context.containsBean(securityBeanId)) {
			setSpringSecurityFilterChain(context.getBean(securityBeanId, Filter.class));
		}
		Assert.state(getSpringSecurityFilterChain() != null,
				() -> "springSecurityFilterChain cannot be null. Ensure a Bean with the name " + securityBeanId
						+ " implementing Filter is present or inject the Filter to be used.");
		// This is used by other test support to obtain the FilterChainProxy
		context.getServletContext().setAttribute(BeanIds.SPRING_SECURITY_FILTER_CHAIN, getSpringSecurityFilterChain());
		return testSecurityContext();
	}

	private void setSpringSecurityFilterChain(Filter filter) {
		this.delegateFilter.setDelegate(filter);
	}

	private Filter getSpringSecurityFilterChain() {
		return this.delegateFilter.delegate;
	}

	/**
	 * Allows adding in {@link #afterConfigurerAdded(ConfigurableMockMvcBuilder)} to
	 * preserve Filter order and then lazily set the delegate in
	 * {@link #beforeMockMvcCreated(ConfigurableMockMvcBuilder, WebApplicationContext)}.
	 *
	 * {@link org.springframework.web.filter.DelegatingFilterProxy} is not used because it
	 * is not easy to lazily set the delegate or get the delegate which is necessary for
	 * the test infrastructure.
	 */
	static class DelegateFilter implements Filter {

		private Filter delegate;

		DelegateFilter() {
		}

		DelegateFilter(Filter delegate) {
			this.delegate = delegate;
		}

		void setDelegate(Filter delegate) {
			this.delegate = delegate;
		}

		Filter getDelegate() {
			Filter result = this.delegate;
			Assert.state(result != null,
					() -> "delegate cannot be null. Ensure a Bean with the name " + BeanIds.SPRING_SECURITY_FILTER_CHAIN
							+ " implementing Filter is present or inject the Filter to be used.");
			return result;
		}

		@Override
		public void init(FilterConfig filterConfig) throws ServletException {
			getDelegate().init(filterConfig);
		}

		@Override
		public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
				throws IOException, ServletException {
			getDelegate().doFilter(request, response, chain);
		}

		@Override
		public void destroy() {
			getDelegate().destroy();
		}

		@Override
		public boolean equals(Object obj) {
			return getDelegate().equals(obj);
		}

		@Override
		public int hashCode() {
			return getDelegate().hashCode();
		}

		@Override
		public String toString() {
			return getDelegate().toString();
		}

	}

}
