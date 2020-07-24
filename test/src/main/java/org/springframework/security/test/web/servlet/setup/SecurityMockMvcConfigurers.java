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

import org.springframework.test.web.servlet.setup.MockMvcConfigurer;
import org.springframework.util.Assert;

import javax.servlet.Filter;

/**
 * Provides Security related
 * {@link org.springframework.test.web.servlet.setup.MockMvcConfigurer} implementations.
 *
 * @author Rob Winch
 * @since 4.0
 */
public final class SecurityMockMvcConfigurers {

	/**
	 * Configures the MockMvcBuilder for use with Spring Security. Specifically the
	 * configurer adds the Spring Bean named "springSecurityFilterChain" as a Filter. It
	 * will also ensure that the TestSecurityContextHolder is leveraged for each request
	 * by applying
	 * {@link org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors#testSecurityContext()}
	 * .
	 * @return the {@link org.springframework.test.web.servlet.setup.MockMvcConfigurer} to
	 * use
	 */
	public static MockMvcConfigurer springSecurity() {
		return new SecurityMockMvcConfigurer();
	}

	/**
	 * Configures the MockMvcBuilder for use with Spring Security. Specifically the
	 * configurer adds the provided Filter. It will also ensure that the
	 * TestSecurityContextHolder is leveraged for each request by applying
	 * {@link org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors#testSecurityContext()}
	 * .
	 * @param springSecurityFilterChain the Filter to be added
	 * @return the {@link org.springframework.test.web.servlet.setup.MockMvcConfigurer} to
	 * use
	 */
	public static MockMvcConfigurer springSecurity(Filter springSecurityFilterChain) {
		Assert.notNull(springSecurityFilterChain, "springSecurityFilterChain cannot be null");
		return new SecurityMockMvcConfigurer(springSecurityFilterChain);
	}

}
