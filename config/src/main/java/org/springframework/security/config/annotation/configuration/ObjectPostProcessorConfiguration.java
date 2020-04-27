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
package org.springframework.security.config.annotation.configuration;

import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**
 * Spring {@link Configuration} that exports the default {@link ObjectPostProcessor}. This
 * class is not intended to be imported manually rather it is imported automatically when
 * using {@link EnableWebSecurity} or {@link EnableGlobalMethodSecurity}.
 *
 * @see EnableWebSecurity
 * @see EnableGlobalMethodSecurity
 *
 * @author Rob Winch
 * @since 3.2
 */
@Configuration
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
public class ObjectPostProcessorConfiguration {

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	public ObjectPostProcessor<Object> objectPostProcessor(
			AutowireCapableBeanFactory beanFactory) {
		return new AutowireBeanFactoryObjectPostProcessor(beanFactory);
	}
}
