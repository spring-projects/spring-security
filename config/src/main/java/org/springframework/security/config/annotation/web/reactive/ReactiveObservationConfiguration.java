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

package org.springframework.security.config.annotation.web.reactive;

import io.micrometer.observation.ObservationRegistry;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.authentication.ObservationReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.ObservationReactiveAuthorizationManager;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.observation.SecurityObservationSettings;
import org.springframework.security.web.server.ObservationWebFilterChainDecorator;
import org.springframework.security.web.server.WebFilterChainProxy.WebFilterChainDecorator;
import org.springframework.web.server.ServerWebExchange;

@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
class ReactiveObservationConfiguration {

	private static final SecurityObservationSettings all = SecurityObservationSettings.withDefaults()
		.shouldObserveRequests(true)
		.shouldObserveAuthentications(true)
		.shouldObserveAuthorizations(true)
		.build();

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static ObjectPostProcessor<ReactiveAuthorizationManager<ServerWebExchange>> webAuthorizationManagerPostProcessor(
			ObjectProvider<ObservationRegistry> registry, ObjectProvider<SecurityObservationSettings> predicate) {
		return new ObjectPostProcessor<>() {
			@Override
			public ReactiveAuthorizationManager postProcess(ReactiveAuthorizationManager object) {
				ObservationRegistry r = registry.getIfUnique(() -> ObservationRegistry.NOOP);
				boolean active = !r.isNoop() && predicate.getIfUnique(() -> all).shouldObserveAuthorizations();
				return active ? new ObservationReactiveAuthorizationManager<>(r, object) : object;
			}
		};
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static ObjectPostProcessor<ReactiveAuthenticationManager> reactiveAuthenticationManagerPostProcessor(
			ObjectProvider<ObservationRegistry> registry, ObjectProvider<SecurityObservationSettings> predicate) {
		return new ObjectPostProcessor<>() {
			@Override
			public ReactiveAuthenticationManager postProcess(ReactiveAuthenticationManager object) {
				ObservationRegistry r = registry.getIfUnique(() -> ObservationRegistry.NOOP);
				boolean active = !r.isNoop() && predicate.getIfUnique(() -> all).shouldObserveAuthentications();
				return active ? new ObservationReactiveAuthenticationManager(r, object) : object;
			}
		};
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static ObjectPostProcessor<WebFilterChainDecorator> filterChainDecoratorPostProcessor(
			ObjectProvider<ObservationRegistry> registry, ObjectProvider<SecurityObservationSettings> predicate) {
		return new ObjectPostProcessor<>() {
			@Override
			public WebFilterChainDecorator postProcess(WebFilterChainDecorator object) {
				ObservationRegistry r = registry.getIfUnique(() -> ObservationRegistry.NOOP);
				boolean active = !r.isNoop() && predicate.getIfUnique(() -> all).shouldObserveRequests();
				return active ? new ObservationWebFilterChainDecorator(r) : object;
			}
		};
	}

}
