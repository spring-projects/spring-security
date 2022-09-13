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
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.ObservationAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.Jsr250AuthorizationManager;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

/**
 * {@link Configuration} for enabling JSR-250 Spring Security Method Security.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.6
 * @see EnableMethodSecurity
 */
@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
final class Jsr250MethodSecurityConfiguration {

	private final ObservationJsr250AuthorizationManager jsr250AuthorizationManager = new ObservationJsr250AuthorizationManager();

	private final AuthorizationManagerBeforeMethodInterceptor interceptor = AuthorizationManagerBeforeMethodInterceptor
			.jsr250(this.jsr250AuthorizationManager);

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	Advisor jsr250AuthorizationMethodInterceptor() {
		return this.interceptor;
	}

	@Autowired(required = false)
	void setGrantedAuthorityDefaults(GrantedAuthorityDefaults grantedAuthorityDefaults) {
		this.jsr250AuthorizationManager.manager.setRolePrefix(grantedAuthorityDefaults.getRolePrefix());
	}

	@Autowired(required = false)
	void setObservationRegistry(ObservationRegistry observationRegistry) {
		this.jsr250AuthorizationManager.setObservationRegistry(observationRegistry);
	}

	@Autowired(required = false)
	void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		this.interceptor.setSecurityContextHolderStrategy(securityContextHolderStrategy);
	}

	private static class ObservationJsr250AuthorizationManager implements AuthorizationManager<MethodInvocation> {

		private Jsr250AuthorizationManager manager = new Jsr250AuthorizationManager();

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
