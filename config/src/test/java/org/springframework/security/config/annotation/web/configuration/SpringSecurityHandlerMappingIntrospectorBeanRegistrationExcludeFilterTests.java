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

package org.springframework.security.config.annotation.web.configuration;

import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.aot.BeanRegistrationExcludeFilter;
import org.springframework.beans.factory.support.RegisteredBean;
import org.springframework.core.io.support.SpringFactoriesLoader;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for
 * {@link WebMvcSecurityConfiguration.SpringSecurityHandlerMappingIntrospectorBeanRegistrationExcludeFilter}
 *
 * @author Marcus da Coregio
 */
class SpringSecurityHandlerMappingIntrospectorBeanRegistrationExcludeFilterTests {

	@Test
	void springSecurityHandlerMappingIntrospectorBeanRegistrationExcludeFilterShouldBeExcludedFromAotProcessing()
			throws ClassNotFoundException {
		List<BeanRegistrationExcludeFilter> filters = SpringFactoriesLoader
			.forResourceLocation("META-INF/spring/aot.factories")
			.load(BeanRegistrationExcludeFilter.class);
		RegisteredBean registeredBean = mock(RegisteredBean.class);
		Class<?> clazz = Class.forName(
				"org.springframework.security.config.annotation.web.configuration.WebMvcSecurityConfiguration$SpringSecurityHandlerMappingIntrospectorBeanDefinitionRegistryPostProcessor");
		given(registeredBean.getBeanClass()).willReturn((Class) clazz);
		boolean isExcluded = filters.stream().anyMatch((f) -> f.isExcludedFromAotProcessing(registeredBean));
		assertThat(isExcluded).isTrue();
	}

}
