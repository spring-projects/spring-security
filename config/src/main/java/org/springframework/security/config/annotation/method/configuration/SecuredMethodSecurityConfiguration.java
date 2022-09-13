/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.method.configuration;

import java.util.function.Supplier;

import io.micrometer.observation.ObservationRegistry;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.Advisor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.ObservationAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.SecuredAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

/**
 * {@link Configuration} for enabling {@link Secured} Spring Security Method Security.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.6
 * @see EnableMethodSecurity
 */
@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
final class SecuredMethodSecurityConfiguration {

	private final ObservationSecuredAuthorizationManager manager = new ObservationSecuredAuthorizationManager();

	private final AuthorizationManagerBeforeMethodInterceptor interceptor = AuthorizationManagerBeforeMethodInterceptor
			.secured(this.manager);

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	Advisor securedAuthorizationMethodInterceptor() {
		return this.interceptor;
	}

	@Autowired(required = false)
	void setObservationRegistry(ObservationRegistry observationRegistry) {
		this.manager.setObservationRegistry(observationRegistry);
	}

	@Autowired(required = false)
	void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		this.interceptor.setSecurityContextHolderStrategy(securityContextHolderStrategy);
	}

	private static class ObservationSecuredAuthorizationManager implements AuthorizationManager<MethodInvocation> {

		private SecuredAuthorizationManager manager = new SecuredAuthorizationManager();

		private ObservationAuthorizationManager<MethodInvocation> observation = new ObservationAuthorizationManager<>(
				ObservationRegistry.NOOP, this.manager);

		@Override
		public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocation object) {
			return this.observation.check(authentication, object);
		}

		void setObservationRegistry(ObservationRegistry observationRegistry) {
			this.observation = new ObservationAuthorizationManager<>(observationRegistry, this.manager);
		}

	}

}
