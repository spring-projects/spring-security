/*
 * Copyright 2002-2021 the original author or authors.
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

/**
 * Base {@link Configuration} for enabling Spring Security Method Security.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @see EnableMethodSecurity
 * @since 5.6
 */
@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
final class PrePostMethodSecurityConfiguration implements ApplicationContextAware {

	private final PreFilterAuthorizationMethodInterceptor preFilterAuthorizationMethodInterceptor = new PreFilterAuthorizationMethodInterceptor();

	private final PreAuthorizeAuthorizationManager preAuthorizeAuthorizationManager = new PreAuthorizeAuthorizationManager();

	private final PostAuthorizeAuthorizationManager postAuthorizeAuthorizationManager = new PostAuthorizeAuthorizationManager();

	private final PostFilterAuthorizationMethodInterceptor postFilterAuthorizationMethodInterceptor = new PostFilterAuthorizationMethodInterceptor();

	private final DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();

	private boolean customMethodSecurityExpressionHandler = false;

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	Advisor preFilterAuthorizationMethodInterceptor() {
		if (!this.customMethodSecurityExpressionHandler) {
			this.preAuthorizeAuthorizationManager.setExpressionHandler(this.expressionHandler);
		}
		return this.preFilterAuthorizationMethodInterceptor;
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	Advisor preAuthorizeAuthorizationMethodInterceptor() {
		if (!this.customMethodSecurityExpressionHandler) {
			this.preAuthorizeAuthorizationManager.setExpressionHandler(this.expressionHandler);
		}
		return AuthorizationManagerBeforeMethodInterceptor.preAuthorize(this.preAuthorizeAuthorizationManager);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	Advisor postAuthorizeAuthorizationMethodInterceptor() {
		if (!this.customMethodSecurityExpressionHandler) {
			this.postAuthorizeAuthorizationManager.setExpressionHandler(this.expressionHandler);
		}
		return AuthorizationManagerAfterMethodInterceptor.postAuthorize(this.postAuthorizeAuthorizationManager);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	Advisor postFilterAuthorizationMethodInterceptor() {
		if (!this.customMethodSecurityExpressionHandler) {
			this.postFilterAuthorizationMethodInterceptor.setExpressionHandler(this.expressionHandler);
		}
		return this.postFilterAuthorizationMethodInterceptor;
	}

	@Autowired(required = false)
	void setMethodSecurityExpressionHandler(MethodSecurityExpressionHandler methodSecurityExpressionHandler) {
		this.customMethodSecurityExpressionHandler = true;
		this.preFilterAuthorizationMethodInterceptor.setExpressionHandler(methodSecurityExpressionHandler);
		this.preAuthorizeAuthorizationManager.setExpressionHandler(methodSecurityExpressionHandler);
		this.postAuthorizeAuthorizationManager.setExpressionHandler(methodSecurityExpressionHandler);
		this.postFilterAuthorizationMethodInterceptor.setExpressionHandler(methodSecurityExpressionHandler);
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
