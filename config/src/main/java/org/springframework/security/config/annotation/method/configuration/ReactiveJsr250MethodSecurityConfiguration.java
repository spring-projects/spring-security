/*
 * Copyright 2004-present the original author or authors.
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

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.Pointcut;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthoritiesAuthorizationManager;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeReactiveMethodInterceptor;
import org.springframework.security.authorization.method.Jsr250ReactiveAuthorizationManager;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.core.GrantedAuthorityDefaults;

/**
 * {@link Configuration} for enabling JSR-250 Spring Security Reactive Method Security.
 *
 * @author Rohit Behera
 * @since 7.3
 * @see EnableReactiveMethodSecurity
 */
@Configuration(value = "_reactiveJsr250MethodSecurityConfiguration", proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
final class ReactiveJsr250MethodSecurityConfiguration implements AopInfrastructureBean {

	private static final Pointcut pointcut = AuthorizationManagerBeforeReactiveMethodInterceptor.jsr250().getPointcut();

	private final Jsr250ReactiveAuthorizationManager authorizationManager = new Jsr250ReactiveAuthorizationManager();

	private final AuthorizationManagerBeforeReactiveMethodInterceptor methodInterceptor;

	ReactiveJsr250MethodSecurityConfiguration(
			ObjectProvider<ObjectPostProcessor<ReactiveAuthorizationManager<MethodInvocation>>> postProcessors) {
		ReactiveAuthorizationManager<MethodInvocation> manager = postProcessors
			.getIfUnique(ObjectPostProcessor::identity)
			.postProcess(this.authorizationManager);
		this.methodInterceptor = AuthorizationManagerBeforeReactiveMethodInterceptor.jsr250(manager);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor jsr250AuthorizationMethodInterceptor(
			ObjectProvider<ReactiveJsr250MethodSecurityConfiguration> _reactiveJsr250MethodSecurityConfiguration) {
		return new DeferringMethodInterceptor<>(pointcut,
				() -> _reactiveJsr250MethodSecurityConfiguration.getObject().methodInterceptor);
	}

	@Autowired(required = false)
	void setGrantedAuthorityDefaults(GrantedAuthorityDefaults defaults) {
		this.authorizationManager.setRolePrefix(defaults.getRolePrefix());
	}

	@Autowired(required = false)
	void setRoleHierarchy(RoleHierarchy roleHierarchy) {
		AuthoritiesAuthorizationManager authoritiesAuthorizationManager = new AuthoritiesAuthorizationManager();
		authoritiesAuthorizationManager.setRoleHierarchy(roleHierarchy);
		this.authorizationManager.setAuthoritiesAuthorizationManager(authoritiesAuthorizationManager);
	}

}
