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

package org.springframework.security.config.annotation.observation.configuration;

import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ObservationAuthenticationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.ObservationAuthorizationManager;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.ObservationFilterChainDecorator;

@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
class ObservationConfiguration {

	private final ObjectProvider<ObservationRegistry> observationRegistry;

	ObservationConfiguration(ObjectProvider<ObservationRegistry> observationRegistry) {
		this.observationRegistry = observationRegistry;
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	ObjectPostProcessor<AuthorizationManager<MethodInvocation>> methodAuthorizationManagerPostProcessor() {
		return new AbstractObservationObjectPostProcessor<>(this.observationRegistry,
				ObservationAuthorizationManager::new) {
		};
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	ObjectPostProcessor<AuthorizationManager<MethodInvocationResult>> methodResultAuthorizationManagerPostProcessor() {
		return new AbstractObservationObjectPostProcessor<>(this.observationRegistry,
				ObservationAuthorizationManager::new) {
		};
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	ObjectPostProcessor<AuthorizationManager<HttpServletRequest>> webAuthorizationManagerPostProcessor() {
		return new AbstractObservationObjectPostProcessor<>(this.observationRegistry,
				ObservationAuthorizationManager::new) {
		};
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	ObjectPostProcessor<AuthenticationManager> authenticationManagerPostProcessor() {
		return new AbstractObservationObjectPostProcessor<>(this.observationRegistry,
				ObservationAuthenticationManager::new) {
		};
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	ObjectPostProcessor<FilterChainProxy.FilterChainDecorator> filterChainDecoratorPostProcessor() {
		return new AbstractObservationObjectPostProcessor<>(this.observationRegistry,
				ObservationFilterChainDecorator::new) {
		};
	}

}
