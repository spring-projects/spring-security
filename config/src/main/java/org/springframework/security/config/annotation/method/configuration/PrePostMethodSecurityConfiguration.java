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
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.ObservationAuthorizationManager;
import org.springframework.security.authorization.SpringAuthorizationEventPublisher;
import org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.MethodInvocationResult;
import org.springframework.security.authorization.method.PostAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PostFilterAuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.PreAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PreFilterAuthorizationMethodInterceptor;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

/**
 * Base {@link Configuration} for enabling Spring Security Method Security.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.6
 * @see EnableMethodSecurity
 */
@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
final class PrePostMethodSecurityConfiguration {

	private final PreFilterAuthorizationMethodInterceptor preFilterAuthorizationMethodInterceptor = new PreFilterAuthorizationMethodInterceptor();

	private final AuthorizationManagerBeforeMethodInterceptor preAuthorizeAuthorizationMethodInterceptor;

	private final ObservationPreAuthorizationManager preAuthorizeAuthorizationManager = new ObservationPreAuthorizationManager();

	private final AuthorizationManagerAfterMethodInterceptor postAuthorizeAuthorizaitonMethodInterceptor;

	private final ObservationPostAuthorizationManager postAuthorizeAuthorizationManager = new ObservationPostAuthorizationManager();

	private final PostFilterAuthorizationMethodInterceptor postFilterAuthorizationMethodInterceptor = new PostFilterAuthorizationMethodInterceptor();

	private final DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();

	@Autowired
	PrePostMethodSecurityConfiguration(ApplicationContext context) {
		this.preAuthorizeAuthorizationManager.manager.setExpressionHandler(this.expressionHandler);
		this.preAuthorizeAuthorizationMethodInterceptor = AuthorizationManagerBeforeMethodInterceptor
				.preAuthorize(this.preAuthorizeAuthorizationManager);
		this.postAuthorizeAuthorizationManager.manager.setExpressionHandler(this.expressionHandler);
		this.postAuthorizeAuthorizaitonMethodInterceptor = AuthorizationManagerAfterMethodInterceptor
				.postAuthorize(this.postAuthorizeAuthorizationManager);
		this.preFilterAuthorizationMethodInterceptor.setExpressionHandler(this.expressionHandler);
		this.postFilterAuthorizationMethodInterceptor.setExpressionHandler(this.expressionHandler);
		this.expressionHandler.setApplicationContext(context);
		AuthorizationEventPublisher publisher = new SpringAuthorizationEventPublisher(context);
		this.preAuthorizeAuthorizationMethodInterceptor.setAuthorizationEventPublisher(publisher);
		this.postAuthorizeAuthorizaitonMethodInterceptor.setAuthorizationEventPublisher(publisher);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	Advisor preFilterAuthorizationMethodInterceptor() {
		return this.preFilterAuthorizationMethodInterceptor;
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	Advisor preAuthorizeAuthorizationMethodInterceptor() {
		return this.preAuthorizeAuthorizationMethodInterceptor;
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	Advisor postAuthorizeAuthorizationMethodInterceptor() {
		return this.postAuthorizeAuthorizaitonMethodInterceptor;
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	Advisor postFilterAuthorizationMethodInterceptor() {
		return this.postFilterAuthorizationMethodInterceptor;
	}

	@Autowired(required = false)
	void setMethodSecurityExpressionHandler(MethodSecurityExpressionHandler methodSecurityExpressionHandler) {
		this.preFilterAuthorizationMethodInterceptor.setExpressionHandler(methodSecurityExpressionHandler);
		this.preAuthorizeAuthorizationManager.manager.setExpressionHandler(methodSecurityExpressionHandler);
		this.postAuthorizeAuthorizationManager.manager.setExpressionHandler(methodSecurityExpressionHandler);
		this.postFilterAuthorizationMethodInterceptor.setExpressionHandler(methodSecurityExpressionHandler);
	}

	@Autowired(required = false)
	void setObservationRegistry(ObservationRegistry observationRegistry) {
		this.preAuthorizeAuthorizationManager.setObservationRegistry(observationRegistry);
		this.postAuthorizeAuthorizationManager.setObservationRegistry(observationRegistry);
	}

	@Autowired(required = false)
	void setSecurityContextHolderStrategy(SecurityContextHolderStrategy strategy) {
		this.preFilterAuthorizationMethodInterceptor.setSecurityContextHolderStrategy(strategy);
		this.preAuthorizeAuthorizationMethodInterceptor.setSecurityContextHolderStrategy(strategy);
		this.postAuthorizeAuthorizaitonMethodInterceptor.setSecurityContextHolderStrategy(strategy);
		this.postFilterAuthorizationMethodInterceptor.setSecurityContextHolderStrategy(strategy);
	}

	@Autowired(required = false)
	void setGrantedAuthorityDefaults(GrantedAuthorityDefaults grantedAuthorityDefaults) {
		this.expressionHandler.setDefaultRolePrefix(grantedAuthorityDefaults.getRolePrefix());
	}

	@Autowired(required = false)
	void setAuthorizationEventPublisher(AuthorizationEventPublisher eventPublisher) {
		this.preAuthorizeAuthorizationMethodInterceptor.setAuthorizationEventPublisher(eventPublisher);
		this.postAuthorizeAuthorizaitonMethodInterceptor.setAuthorizationEventPublisher(eventPublisher);
	}

	private static class ObservationPreAuthorizationManager implements AuthorizationManager<MethodInvocation> {

		private PreAuthorizeAuthorizationManager manager = new PreAuthorizeAuthorizationManager();

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

	private static class ObservationPostAuthorizationManager implements AuthorizationManager<MethodInvocationResult> {

		private PostAuthorizeAuthorizationManager manager = new PostAuthorizeAuthorizationManager();

		private ObservationAuthorizationManager<MethodInvocationResult> observation = new ObservationAuthorizationManager<>(
				ObservationRegistry.NOOP, this.manager);

		@Override
		public AuthorizationDecision check(Supplier<Authentication> authentication, MethodInvocationResult object) {
			return this.observation.check(authentication, object);
		}

		void setObservationRegistry(ObservationRegistry observationRegistry) {
			this.observation = new ObservationAuthorizationManager<>(observationRegistry, this.manager);
		}

	}

}
