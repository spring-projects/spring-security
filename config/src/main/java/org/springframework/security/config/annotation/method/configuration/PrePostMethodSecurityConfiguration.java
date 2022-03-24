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

import org.springframework.aop.Advisor;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.PostAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PostFilterAuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.PreAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PreFilterAuthorizationMethodInterceptor;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
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
final class PrePostMethodSecurityConfiguration implements ApplicationContextAware {

	private final PreFilterAuthorizationMethodInterceptor preFilterAuthorizationMethodInterceptor = new PreFilterAuthorizationMethodInterceptor();

	private final AuthorizationManagerBeforeMethodInterceptor preAuthorizeAuthorizationMethodInterceptor;

	private final PreAuthorizeAuthorizationManager preAuthorizeAuthorizationManager = new PreAuthorizeAuthorizationManager();

	private final AuthorizationManagerAfterMethodInterceptor postAuthorizeAuthorizaitonMethodInterceptor;

	private final PostAuthorizeAuthorizationManager postAuthorizeAuthorizationManager = new PostAuthorizeAuthorizationManager();

	private final PostFilterAuthorizationMethodInterceptor postFilterAuthorizationMethodInterceptor = new PostFilterAuthorizationMethodInterceptor();

	private final DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();

	PrePostMethodSecurityConfiguration() {
		this.preAuthorizeAuthorizationManager.setExpressionHandler(this.expressionHandler);
		this.preAuthorizeAuthorizationMethodInterceptor = AuthorizationManagerBeforeMethodInterceptor
				.preAuthorize(this.preAuthorizeAuthorizationManager);
		this.postAuthorizeAuthorizationManager.setExpressionHandler(this.expressionHandler);
		this.postAuthorizeAuthorizaitonMethodInterceptor = AuthorizationManagerAfterMethodInterceptor
				.postAuthorize(this.postAuthorizeAuthorizationManager);
		this.preFilterAuthorizationMethodInterceptor.setExpressionHandler(this.expressionHandler);
		this.postFilterAuthorizationMethodInterceptor.setExpressionHandler(this.expressionHandler);
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
		this.preAuthorizeAuthorizationManager.setExpressionHandler(methodSecurityExpressionHandler);
		this.postAuthorizeAuthorizationManager.setExpressionHandler(methodSecurityExpressionHandler);
		this.postFilterAuthorizationMethodInterceptor.setExpressionHandler(methodSecurityExpressionHandler);
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

	@Override
	public void setApplicationContext(ApplicationContext context) throws BeansException {
		this.expressionHandler.setApplicationContext(context);
	}

}
