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

import javax.servlet.Filter;

import org.springframework.security.config.BeanIds;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.ConfigurableMockMvcBuilder;
import org.springframework.test.web.servlet.setup.MockMvcConfigurerAdapter;
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
	private Filter springSecurityFilterChain;

	/**
	 * Creates a new instance
	 */
	SecurityMockMvcConfigurer() {
	}

	/**
	 * Creates a new instance with the provided {@link javax.servlet.Filter}
	 * @param springSecurityFilterChain the {@link javax.servlet.Filter} to use
	 */
	SecurityMockMvcConfigurer(Filter springSecurityFilterChain) {
		this.springSecurityFilterChain = springSecurityFilterChain;
	}

	@Override
	public RequestPostProcessor beforeMockMvcCreated(
			ConfigurableMockMvcBuilder<?> builder, WebApplicationContext context) {
		String securityBeanId = BeanIds.SPRING_SECURITY_FILTER_CHAIN;
		if (this.springSecurityFilterChain == null
				&& context.containsBean(securityBeanId)) {
			this.springSecurityFilterChain = context.getBean(securityBeanId,
					Filter.class);
		}

		if (this.springSecurityFilterChain == null) {
			throw new IllegalStateException(
					"springSecurityFilterChain cannot be null. Ensure a Bean with the name "
							+ securityBeanId
							+ " implementing Filter is present or inject the Filter to be used.");
		}

		builder.addFilters(this.springSecurityFilterChain);
		context.getServletContext().setAttribute(BeanIds.SPRING_SECURITY_FILTER_CHAIN,
				this.springSecurityFilterChain);

		return testSecurityContext();
	}
}
