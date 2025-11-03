/*
 * Copyright 2002-present the original author or authors.
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

package org.springframework.security.config.annotation.authorization;

import org.jspecify.annotations.Nullable;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration(proxyBeanMethods = false)
class EnableMfaFiltersConfiguration {

	@Bean
	BeanPostProcessor mfaBeanPostProcessor() {
		return new EnableMfaFiltersPostProcessor();
	}

	/**
	 * A {@link BeanPostProcessor} that enables MFA on authentication filters.
	 *
	 * @author Rob Winch
	 * @since 7.0
	 */
	private static class EnableMfaFiltersPostProcessor implements BeanPostProcessor {

		@Override
		public @Nullable Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
			if (bean instanceof AbstractAuthenticationProcessingFilter filter) {
				filter.setMfaEnabled(true);
			}
			if (bean instanceof AuthenticationFilter filter) {
				filter.setMfaEnabled(true);
			}
			if (bean instanceof AbstractPreAuthenticatedProcessingFilter filter) {
				filter.setMfaEnabled(true);
			}
			if (bean instanceof BasicAuthenticationFilter filter) {
				filter.setMfaEnabled(true);
			}
			return bean;
		}

	}

}
