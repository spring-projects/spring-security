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

package org.springframework.security.config.annotation.web.socket;

import io.micrometer.observation.ObservationRegistry;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.messaging.Message;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.ObservationAuthorizationManager;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.observation.SecurityObservationSettings;

@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
class WebSocketObservationConfiguration {

	private static final SecurityObservationSettings all = SecurityObservationSettings.withDefaults()
		.shouldObserveRequests(true)
		.shouldObserveAuthentications(true)
		.shouldObserveAuthorizations(true)
		.build();

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static ObjectPostProcessor<AuthorizationManager<Message<?>>> webSocketAuthorizationManagerPostProcessor(
			ObjectProvider<ObservationRegistry> registry, ObjectProvider<SecurityObservationSettings> predicate) {
		return new ObjectPostProcessor<>() {
			@Override
			public AuthorizationManager postProcess(AuthorizationManager object) {
				ObservationRegistry r = registry.getIfUnique(() -> ObservationRegistry.NOOP);
				boolean active = !r.isNoop() && predicate.getIfUnique(() -> all).shouldObserveAuthorizations();
				return active ? new ObservationAuthorizationManager<>(r, object) : object;
			}
		};
	}

}
