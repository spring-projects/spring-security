/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.config.debug;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.security.config.BeanIds;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.debug.DebugFilter;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension.class)
public class SecurityDebugBeanFactoryPostProcessorTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	public void contextRefreshWhenInDebugModeAndDependencyHasAutowiredConstructorThenDebugModeStillWorks() {
		// SEC-1885
		this.spring.configLocations(
				"classpath:org/springframework/security/config/debug/SecurityDebugBeanFactoryPostProcessorTests-context.xml")
				.autowire();
		assertThat(this.spring.getContext().getBean(BeanIds.SPRING_SECURITY_FILTER_CHAIN))
				.isInstanceOf(DebugFilter.class);
		assertThat(this.spring.getContext().getBean(BeanIds.FILTER_CHAIN_PROXY)).isInstanceOf(FilterChainProxy.class);
	}

}
